use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use flowersec::{
    protocol_v2::CipherSuiteV2,
    session_v2::{
        RpcHandlerV2, SessionConfigV2, SessionDeadlinesV2, establish_session_v2,
        memory_carrier_pair_v2, memory_carrier_pair_v2_with_capacity,
    },
    transport_v2::{
        CarrierKind, CarrierSessionV2, CarrierStreamV2, PathKind, SessionRole, SessionV2,
    },
    yamux::{ByteDuplex, Mode, YamuxError, YamuxLimits, YamuxSession},
};
use tokio::sync::{Mutex, Notify, mpsc};

#[tokio::test]
async fn exact_handshake_and_ready_boundary_establish_a_memory_pair() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v2();
    let psk = [0x42; 32];
    let contract = [0x24; 32];
    let client = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Tunnel,
        channel_id: "rust-session-v2".into(),
        session_contract_hash: contract,
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk,
        max_inbound_streams: 4,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: Some("client-instance".into()),
        expected_peer_endpoint_instance_id: Some("server-instance".into()),
        rpc_handler: Some(Arc::new(EchoRpc)),
        deadlines: Default::default(),
    };
    let server = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        local_endpoint_instance_id: Some("server-instance".into()),
        expected_peer_endpoint_instance_id: Some("client-instance".into()),
        ..client.clone()
    };

    let (client_result, server_result) = tokio::join!(
        establish_session_v2(client_carrier, client),
        establish_session_v2(server_carrier, server),
    );
    let client: Arc<dyn SessionV2> = client_result.expect("client session");
    let server: Arc<dyn SessionV2> = server_result.expect("server session");
    assert_eq!(client.endpoint_instance_id(), Some("server-instance"));
    assert_eq!(server.endpoint_instance_id(), Some("client-instance"));
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[derive(Debug)]
struct GatedCarrierSession {
    inner: Arc<dyn CarrierSessionV2>,
    gate: Arc<AtomicBool>,
    write_entered: Arc<Notify>,
    release_write: Arc<Notify>,
}

#[derive(Debug)]
struct GatedCarrierStream {
    inner: Arc<dyn CarrierStreamV2>,
    gate: Arc<AtomicBool>,
    write_entered: Arc<Notify>,
    release_write: Arc<Notify>,
}

#[derive(Debug)]
struct FailingNthOpenCarrierSession {
    inner: Arc<dyn CarrierSessionV2>,
    opens: AtomicU64,
    fail_on: u64,
}

#[derive(Debug)]
struct CapacityReportingCarrierSession {
    inner: Arc<dyn CarrierSessionV2>,
    capacity: u32,
    opens: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl CarrierSessionV2 for CapacityReportingCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.capacity
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        self.opens.fetch_add(1, Ordering::AcqRel);
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        self.inner.accept_stream().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV2 for FailingNthOpenCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }
    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        let ordinal = self.opens.fetch_add(1, Ordering::AcqRel) + 1;
        if ordinal == self.fail_on {
            return Err(io::Error::other("injected carrier open failure"));
        }
        self.inner.open_stream().await
    }
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        self.inner.accept_stream().await
    }
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[derive(Debug)]
struct BlockingNthWriteCarrierSession {
    inner: Arc<dyn CarrierSessionV2>,
    enabled: Arc<AtomicBool>,
    writes: Arc<AtomicU64>,
    block_on: u64,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[derive(Debug)]
struct BlockingNthWriteCarrierStream {
    inner: Arc<dyn CarrierStreamV2>,
    enabled: Arc<AtomicBool>,
    writes: Arc<AtomicU64>,
    block_on: u64,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[derive(Debug)]
struct BlockingApplicationReadCarrierSession {
    inner: Arc<dyn CarrierSessionV2>,
    accepts: AtomicU64,
    block_on: u64,
    enabled: Arc<AtomicBool>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[derive(Debug)]
struct BlockingApplicationReadCarrierStream {
    inner: Arc<dyn CarrierStreamV2>,
    enabled: Arc<AtomicBool>,
    blocked: AtomicBool,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait::async_trait]
impl CarrierSessionV2 for BlockingApplicationReadCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        let stream = self.inner.accept_stream().await?;
        let ordinal = self.accepts.fetch_add(1, Ordering::AcqRel) + 1;
        if ordinal == self.block_on {
            Ok(Arc::new(BlockingApplicationReadCarrierStream {
                inner: stream,
                enabled: self.enabled.clone(),
                blocked: AtomicBool::new(false),
                entered: self.entered.clone(),
                release: self.release.clone(),
            }))
        } else {
            Ok(stream)
        }
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierStreamV2 for BlockingApplicationReadCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        if self.enabled.load(Ordering::Acquire)
            && self
                .blocked
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.inner.read(payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        self.inner.write(payload).await
    }

    async fn close_write(&self) -> io::Result<()> {
        self.inner.close_write().await
    }

    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV2 for BlockingNthWriteCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }
    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        Ok(Arc::new(BlockingNthWriteCarrierStream {
            inner: self.inner.open_stream().await?,
            enabled: self.enabled.clone(),
            writes: self.writes.clone(),
            block_on: self.block_on,
            entered: self.entered.clone(),
            release: self.release.clone(),
        }))
    }
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        Ok(Arc::new(BlockingNthWriteCarrierStream {
            inner: self.inner.accept_stream().await?,
            enabled: self.enabled.clone(),
            writes: self.writes.clone(),
            block_on: self.block_on,
            entered: self.entered.clone(),
            release: self.release.clone(),
        }))
    }
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierStreamV2 for BlockingNthWriteCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner.read(payload).await
    }
    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        if self.enabled.load(Ordering::Acquire) {
            let ordinal = self.writes.fetch_add(1, Ordering::AcqRel) + 1;
            if ordinal == self.block_on {
                self.entered.notify_one();
                self.release.notified().await;
            }
        }
        self.inner.write(payload).await
    }
    async fn close_write(&self) -> io::Result<()> {
        self.inner.close_write().await
    }
    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await
    }
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV2 for GatedCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }
    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        Ok(Arc::new(GatedCarrierStream {
            inner: self.inner.open_stream().await?,
            gate: self.gate.clone(),
            write_entered: self.write_entered.clone(),
            release_write: self.release_write.clone(),
        }))
    }
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        Ok(Arc::new(GatedCarrierStream {
            inner: self.inner.accept_stream().await?,
            gate: self.gate.clone(),
            write_entered: self.write_entered.clone(),
            release_write: self.release_write.clone(),
        }))
    }
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierStreamV2 for GatedCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner.read(payload).await
    }
    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        if self.gate.load(Ordering::Acquire) {
            self.write_entered.notify_one();
            self.release_write.notified().await;
        }
        self.inner.write(payload).await
    }
    async fn close_write(&self) -> io::Result<()> {
        self.inner.close_write().await
    }
    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await
    }
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[derive(Debug)]
struct EchoRpc;

#[async_trait::async_trait]
impl RpcHandlerV2 for EchoRpc {
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> io::Result<serde_json::Value> {
        Ok(serde_json::json!({"type_id": type_id, "request": request}))
    }
    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn lazy_reserved_rpc_is_encrypted_and_uses_u32_type_ids() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v2();
    let client = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rpc-v2".into(),
        session_contract_hash: [3; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [4; 32],
        max_inbound_streams: 4,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: Some(Arc::new(EchoRpc)),
        deadlines: Default::default(),
    };
    let server = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        rpc_handler: Some(Arc::new(EchoRpc)),
        ..client.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client),
        establish_session_v2(server_carrier, server),
    );
    let client = client.expect("client");
    let server = server.expect("server");
    let type_id = u32::MAX;
    let response = client
        .rpc()
        .call(type_id, serde_json::json!({"hello": "world"}))
        .await
        .expect("RPC call");
    assert_eq!(response["type_id"], serde_json::json!(type_id));
    assert_eq!(response["request"]["hello"], "world");
    let reverse = server
        .rpc()
        .call(9, serde_json::json!({"from": "server"}))
        .await
        .expect("reverse RPC call");
    assert_eq!(reverse["request"]["from"], "server");
    client
        .rpc()
        .notify(7, serde_json::json!({"event": true}))
        .await
        .expect("RPC notify");
    let (client_rekey, server_rekey) = tokio::join!(client.rekey(), server.rekey());
    client_rekey.expect("client RPC rekey");
    server_rekey.expect("server RPC rekey");
    let after = client
        .rpc()
        .call(10, serde_json::json!({"epoch": 1}))
        .await
        .expect("RPC after rekey");
    assert_eq!(after["request"]["epoch"], 1);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

async fn establish_pair() -> (Arc<dyn SessionV2>, Arc<dyn SessionV2>) {
    let (client_carrier, server_carrier) = memory_carrier_pair_v2();
    let client = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rust-session-streams".into(),
        session_contract_hash: [7; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [9; 32],
        max_inbound_streams: 4,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: Some(Arc::new(EchoRpc)),
        deadlines: Default::default(),
    };
    let server = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client),
        establish_session_v2(server_carrier, server),
    );
    (client.expect("client"), server.expect("server"))
}

#[derive(Debug)]
struct YamuxMemoryDuplex {
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

#[async_trait::async_trait]
impl ByteDuplex for YamuxMemoryDuplex {
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

fn yamux_memory_pair() -> (Arc<YamuxMemoryDuplex>, Arc<YamuxMemoryDuplex>) {
    let (client_tx, server_rx) = mpsc::channel(64);
    let (server_tx, client_rx) = mpsc::channel(64);
    (
        Arc::new(YamuxMemoryDuplex {
            incoming: Mutex::new(client_rx),
            outgoing: client_tx,
        }),
        Arc::new(YamuxMemoryDuplex {
            incoming: Mutex::new(server_rx),
            outgoing: server_tx,
        }),
    )
}

#[tokio::test]
async fn physical_capacity_mismatch_fails_before_control_stream_open() {
    let (inner, _peer) = memory_carrier_pair_v2();
    let opens = Arc::new(AtomicU64::new(0));
    let carrier: Arc<dyn CarrierSessionV2> = Arc::new(CapacityReportingCarrierSession {
        inner,
        capacity: 4,
        opens: opens.clone(),
    });
    let error = establish_session_v2(
        carrier,
        regression_config(SessionRole::Client, "capacity-mismatch", 1, None),
    )
    .await
    .expect_err("N=1 must require exactly three physical streams");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(opens.load(Ordering::Acquire), 0);
}

fn memory_carrier_pair_for_logical(
    logical: u16,
) -> (Arc<dyn CarrierSessionV2>, Arc<dyn CarrierSessionV2>) {
    memory_carrier_pair_v2_with_capacity(u32::from(logical) + 2)
}

#[tokio::test]
async fn yamux_control_and_rpc_slots_preserve_one_data_stream_capacity() {
    let limits = YamuxLimits::default()
        .with_session_v2_logical_stream_limit(1)
        .expect("SessionV2 Yamux limits");
    assert_eq!(limits.max_inbound_streams, 3);
    assert!(limits.max_active_streams >= 3);
    let (client_io, server_io) = yamux_memory_pair();
    let client_carrier: Arc<dyn CarrierSessionV2> =
        Arc::new(YamuxSession::new(client_io, Mode::Client, limits).expect("client Yamux"));
    let server_carrier: Arc<dyn CarrierSessionV2> =
        Arc::new(YamuxSession::new(server_io, Mode::Server, limits).expect("server Yamux"));
    let client_config = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "yamux-capacity-one".into(),
        session_contract_hash: [0x51; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x52; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: Some(Arc::new(EchoRpc)),
        deadlines: Default::default(),
    };
    let server_config = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");
    let rpc = client
        .rpc()
        .call(1, serde_json::json!({"capacity": "reserved"}))
        .await
        .expect("reserved RPC stream");
    assert_eq!(rpc["request"]["capacity"], "reserved");

    let (first, first_incoming) = tokio::join!(
        client.open_stream("first", serde_json::Map::new()),
        server.accept_stream(),
    );
    let first = first.expect("first logical stream");
    let _first_incoming = first_incoming.expect("accept first logical stream");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            client.open_stream("blocked", serde_json::Map::new()),
        )
        .await
        .is_err(),
        "second logical stream bypassed the SessionV2 semaphore"
    );

    first.reset().await.expect("reset first logical stream");
    client
        .probe_liveness()
        .await
        .expect("observe peer after reset control record");
    let (third, third_incoming) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            client.open_stream("third", serde_json::Map::new()),
            server.accept_stream(),
        )
    })
    .await
    .expect("capacity was not released after reset");
    assert_eq!(third.expect("third logical stream").id(), 5);
    assert_eq!(third_incoming.expect("accept third logical stream").id(), 5);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn bidirectional_open_data_fin_and_consecutive_rekey() {
    let (client, server) = establish_pair().await;
    let (opened, incoming) = tokio::join!(
        client.open_stream("echo", serde_json::Map::new()),
        server.accept_stream(),
    );
    let opened = opened.expect("open");
    let incoming = incoming.expect("accept");
    assert_eq!(opened.id(), 1);
    assert_eq!(incoming.id(), 1);

    opened
        .write(Bytes::from_static(b"before"))
        .await
        .expect("write");
    assert_eq!(
        incoming.stream().read().await.expect("read"),
        Some(Bytes::from_static(b"before"))
    );

    client.rekey().await.expect("first rekey");
    client.rekey().await.expect("second rekey");
    opened
        .write(Bytes::from_static(b"after"))
        .await
        .expect("post-rekey write");
    assert_eq!(
        incoming.stream().read().await.expect("post-rekey read"),
        Some(Bytes::from_static(b"after"))
    );
    opened.close_write().await.expect("FIN");
    assert_eq!(incoming.stream().read().await.expect("peer FIN"), None);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn simultaneous_rekey_keeps_the_ordered_control_stream_live() {
    let (client, server) = establish_pair().await;
    let (stream, incoming) = tokio::join!(
        client.open_stream("simultaneous", serde_json::Map::new()),
        server.accept_stream(),
    );
    let stream = stream.expect("open active stream");
    let incoming = incoming.expect("accept active stream");
    let (client_rekey, server_rekey) = tokio::join!(client.rekey(), server.rekey());
    client_rekey.expect("client simultaneous rekey");
    server_rekey.expect("server simultaneous rekey");
    client
        .probe_liveness()
        .await
        .expect("client liveness after rekey");
    server
        .probe_liveness()
        .await
        .expect("server liveness after rekey");
    stream
        .write(Bytes::from_static(b"post-simultaneous"))
        .await
        .expect("write after simultaneous rekey");
    assert_eq!(
        incoming.stream().read().await.expect("read after rekey"),
        Some(Bytes::from_static(b"post-simultaneous"))
    );
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn handshake_rejects_max_inbound_streams_tampering() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v2();
    let client = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "max-stream-binding".into(),
        session_contract_hash: [5; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [6; 32],
        max_inbound_streams: 4,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: Default::default(),
    };
    let server = SessionConfigV2 {
        role: SessionRole::Server,
        max_inbound_streams: 5,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client),
        establish_session_v2(server_carrier, server),
    );
    assert!(client.is_err() || server.is_err());
}

#[tokio::test]
async fn injected_establish_deadline_bounds_a_blackholed_peer() {
    let (client_carrier, _blackhole_peer) = memory_carrier_pair_v2();
    let error = establish_session_v2(
        client_carrier,
        SessionConfigV2 {
            role: SessionRole::Client,
            path: PathKind::Direct,
            channel_id: "establish-deadline".into(),
            session_contract_hash: [1; 32],
            suite: CipherSuiteV2::ChaCha20Poly1305,
            psk: [2; 32],
            max_inbound_streams: 4,
            idle_timeout: Duration::ZERO,
            local_admission_binding: [3; 32],
            peer_admission_binding: Some([4; 32]),
            local_endpoint_instance_id: None,
            expected_peer_endpoint_instance_id: None,
            rpc_handler: None,
            deadlines: SessionDeadlinesV2 {
                establish: Duration::from_millis(10),
                ..Default::default()
            },
        },
    )
    .await
    .expect_err("blackholed establish must time out");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn rekey_prepare_timeout_leaves_the_session_recoverable() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: Arc::new(AtomicBool::new(false)),
        write_entered: Arc::new(Notify::new()),
        release_write: Arc::new(Notify::new()),
    });
    let client_carrier: Arc<dyn CarrierSessionV2> =
        Arc::new(BlockingApplicationReadCarrierSession {
            inner: client_carrier,
            accepts: AtomicU64::new(0),
            block_on: 1,
            enabled: enabled.clone(),
            entered: entered.clone(),
            release: release.clone(),
        });
    let mut client = regression_config(SessionRole::Client, "rekey-prepare-timeout", 1, None);
    let server = regression_config(SessionRole::Server, "rekey-prepare-timeout", 1, None);
    client.deadlines.rekey_prepare = Duration::from_millis(25);
    client.deadlines.rekey_completion = Duration::from_millis(500);
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client),
        establish_session_v2(server_carrier, server),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");

    enabled.store(true, Ordering::Release);
    let opening = {
        let server = server.clone();
        tokio::spawn(async move {
            server
                .open_stream("prepare-timeout", serde_json::Map::new())
                .await
        })
    };
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("inbound responder never reached the deterministic stall");
    let error = client
        .rekey()
        .await
        .expect_err("pre-commit responder freeze must time out");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    release.notify_waiters();
    let incoming = tokio::time::timeout(Duration::from_millis(750), client.accept_stream())
        .await
        .expect("inbound OPEN remained frozen after prepare timeout")
        .expect("accept inbound stream");
    let outgoing = tokio::time::timeout(Duration::from_millis(750), opening)
        .await
        .expect("outbound OPEN remained blocked after prepare timeout")
        .expect("join outbound OPEN")
        .expect("open outbound stream");
    outgoing
        .write(Bytes::from_static(b"after-prepare-timeout"))
        .await
        .expect("write after prepare timeout");
    assert_eq!(
        incoming.stream().read().await.expect("read after timeout"),
        Some(Bytes::from_static(b"after-prepare-timeout"))
    );
    client
        .rekey()
        .await
        .expect("later rekey after prepare timeout");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn dropping_a_queued_rekey_future_does_not_run_it_later() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicU64::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(BlockingNthWriteCarrierSession {
        inner: client_inner,
        enabled: enabled.clone(),
        writes: writes.clone(),
        block_on: 1,
        entered: entered.clone(),
        release: release.clone(),
    });
    let mut client_config = regression_config(SessionRole::Client, "queued-rekey-drop", 1, None);
    let mut server_config = regression_config(SessionRole::Server, "queued-rekey-drop", 1, None);
    client_config.deadlines.rekey_prepare = Duration::from_millis(500);
    server_config.deadlines.rekey_prepare = Duration::from_millis(500);
    client_config.deadlines.rekey_completion = Duration::from_millis(500);
    server_config.deadlines.rekey_completion = Duration::from_millis(500);
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");

    writes.store(0, Ordering::Release);
    enabled.store(true, Ordering::Release);
    let first = {
        let client = client.clone();
        tokio::spawn(async move { client.rekey().await })
    };
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("first rekey never reached its commit write");
    let queued = {
        let client = client.clone();
        tokio::spawn(async move { client.rekey().await })
    };
    tokio::task::yield_now().await;
    queued.abort();
    queued
        .await
        .expect_err("queued rekey task must be canceled");
    release.notify_one();
    first
        .await
        .expect("join first rekey")
        .expect("complete first rekey");

    client
        .rekey()
        .await
        .expect("only one later rekey should run");
    assert_eq!(
        writes.load(Ordering::Acquire),
        4,
        "dropped queued rekey emitted a third control record"
    );
    enabled.store(false, Ordering::Release);
    client.probe_liveness().await.expect("session remains live");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn dropping_a_committed_rekey_future_keeps_owned_completion_running() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let gate = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: gate.clone(),
        write_entered: entered.clone(),
        release_write: release.clone(),
    });
    let mut client_config = regression_config(SessionRole::Client, "committed-rekey-drop", 1, None);
    let mut server_config = regression_config(SessionRole::Server, "committed-rekey-drop", 1, None);
    client_config.deadlines.rekey_prepare = Duration::from_millis(500);
    server_config.deadlines.rekey_prepare = Duration::from_millis(500);
    client_config.deadlines.rekey_completion = Duration::from_millis(500);
    server_config.deadlines.rekey_completion = Duration::from_millis(500);
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");

    gate.store(true, Ordering::Release);
    let rekeying = {
        let client = client.clone();
        tokio::spawn(async move { client.rekey().await })
    };
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("rekey never reached its commit write");
    rekeying.abort();
    rekeying
        .await
        .expect_err("caller future must be canceled after commit");
    gate.store(false, Ordering::Release);
    release.notify_waiters();

    tokio::time::timeout(Duration::from_millis(750), client.rekey())
        .await
        .expect("owned completion did not release the rekey slot")
        .expect("later rekey after dropped committed future");
    client.probe_liveness().await.expect("session remains live");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn failed_outbound_carrier_open_commits_abandonment_before_later_rekey() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(2);
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(FailingNthOpenCarrierSession {
        inner: client_inner,
        opens: AtomicU64::new(0),
        fail_on: 2,
    });
    let client_config = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "open-abandonment".into(),
        session_contract_hash: [0x71; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x72; 32],
        max_inbound_streams: 2,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV2 {
            rekey_prepare: Duration::from_millis(200),
            rekey_completion: Duration::from_millis(200),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");
    assert!(
        client
            .open_stream("fails-before-fss2", serde_json::Map::new())
            .await
            .is_err()
    );
    let (stream, incoming) = tokio::join!(
        client.open_stream("after-abandonment", serde_json::Map::new()),
        server.accept_stream(),
    );
    assert_eq!(stream.expect("later stream").id(), 3);
    assert_eq!(incoming.expect("later incoming").id(), 3);
    tokio::time::timeout(Duration::from_millis(500), client.rekey())
        .await
        .expect("rekey remained stuck behind abandoned stream")
        .expect("rekey after abandonment");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn canceled_outbound_setup_commits_reset_before_later_rekey() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(2);
    let gate = Arc::new(AtomicBool::new(false));
    let write_entered = Arc::new(Notify::new());
    let release_write = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: gate.clone(),
        write_entered: write_entered.clone(),
        release_write: release_write.clone(),
    });
    let client_config = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "cancel-open-setup".into(),
        session_contract_hash: [0x77; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x78; 32],
        max_inbound_streams: 2,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV2 {
            rekey_prepare: Duration::from_millis(300),
            rekey_completion: Duration::from_millis(300),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");
    gate.store(true, Ordering::Release);
    let opening = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("cancel-during-fss2", serde_json::Map::new())
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), write_entered.notified())
        .await
        .expect("open never reached blocked FSS2 write");
    opening.abort();
    assert!(
        opening
            .await
            .expect_err("open task must be canceled")
            .is_cancelled()
    );
    gate.store(false, Ordering::Release);
    release_write.notify_waiters();

    let (stream, incoming) = tokio::join!(
        client.open_stream("after-cancel", serde_json::Map::new()),
        server.accept_stream(),
    );
    assert_eq!(stream.expect("later stream").id(), 3);
    assert_eq!(incoming.expect("later incoming").id(), 3);
    tokio::time::timeout(Duration::from_millis(700), client.rekey())
        .await
        .expect("rekey remained stuck behind canceled open")
        .expect("rekey after canceled open");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn canceled_abandonment_finishes_the_partially_written_reset_record() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicU64::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let blocked: Arc<dyn CarrierSessionV2> = Arc::new(BlockingNthWriteCarrierSession {
        inner: client_inner,
        enabled: enabled.clone(),
        writes: writes.clone(),
        block_on: 2,
        entered: entered.clone(),
        release: release.clone(),
    });
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(FailingNthOpenCarrierSession {
        inner: blocked,
        opens: AtomicU64::new(0),
        fail_on: 2,
    });
    let client_config = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "cancel-partial-reset".into(),
        session_contract_hash: [0x7b; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x7c; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: Default::default(),
    };
    let server_config = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");

    writes.store(0, Ordering::Release);
    enabled.store(true, Ordering::Release);
    let opening = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("fails-before-fss2", serde_json::Map::new())
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("STREAM_RESET ciphertext write never blocked");
    opening.abort();
    release.notify_waiters();

    enabled.store(false, Ordering::Release);
    let (stream, incoming) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(
            client.open_stream("after-partial-reset", serde_json::Map::new()),
            server.accept_stream(),
        )
    })
    .await
    .expect("later open remained blocked behind canceled abandonment");
    assert_eq!(stream.expect("later stream").id(), 3);
    assert_eq!(incoming.expect("later incoming").id(), 3);
    tokio::time::timeout(Duration::from_millis(700), client.rekey())
        .await
        .expect("rekey remained stuck behind canceled abandonment")
        .expect("rekey after canceled abandonment");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn goaway_boundary_tightening_rejects_an_already_allocated_open() {
    let (client_inner, server_inner) = memory_carrier_pair_for_logical(1);
    let client_gate = Arc::new(AtomicBool::new(false));
    let client_entered = Arc::new(Notify::new());
    let client_release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: client_gate.clone(),
        write_entered: client_entered.clone(),
        release_write: client_release.clone(),
    });
    let server_enabled = Arc::new(AtomicBool::new(false));
    let server_writes = Arc::new(AtomicU64::new(0));
    let server_entered = Arc::new(Notify::new());
    let server_release = Arc::new(Notify::new());
    let server_carrier: Arc<dyn CarrierSessionV2> = Arc::new(BlockingNthWriteCarrierSession {
        inner: server_inner,
        enabled: server_enabled.clone(),
        writes: server_writes.clone(),
        block_on: 3,
        entered: server_entered.clone(),
        release: server_release.clone(),
    });
    let client_config = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "goaway-tightens-open".into(),
        session_contract_hash: [0x79; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x7a; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV2 {
            close_flush: Duration::from_millis(500),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");

    client_gate.store(true, Ordering::Release);
    let opening = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("past-boundary", serde_json::Map::new())
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), client_entered.notified())
        .await
        .expect("open never reached blocked FSS2 write");

    server_writes.store(0, Ordering::Release);
    server_enabled.store(true, Ordering::Release);
    let closing = {
        let server = server.clone();
        tokio::spawn(async move { server.close().await })
    };
    tokio::time::timeout(Duration::from_secs(1), server_entered.notified())
        .await
        .expect("server close did not flush GOAWAY before SESSION_CLOSE");
    tokio::time::sleep(Duration::from_millis(20)).await;
    client_gate.store(false, Ordering::Release);
    client_release.notify_waiters();
    let error = tokio::time::timeout(Duration::from_secs(1), opening)
        .await
        .expect("open did not observe tightened GOAWAY boundary")
        .expect("join open task")
        .expect_err("open past GOAWAY boundary must fail");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    server_release.notify_waiters();
    closing
        .await
        .expect("join close task")
        .expect("finish server close");
    let _ = client.close().await;
}

#[tokio::test]
async fn close_flush_is_bounded_when_the_control_stream_stalls() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let gate = Arc::new(AtomicBool::new(false));
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: gate.clone(),
        write_entered: Arc::new(Notify::new()),
        release_write: Arc::new(Notify::new()),
    });
    let client_config = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "bounded-close-flush".into(),
        session_contract_hash: [0x73; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x74; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV2 {
            close_flush: Duration::from_millis(20),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");
    gate.store(true, Ordering::Release);
    let error = tokio::time::timeout(Duration::from_millis(250), client.close())
        .await
        .expect("close ignored its flush deadline")
        .expect_err("stalled close flush must report timeout");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    gate.store(false, Ordering::Release);
    let _ = server.close().await;
}

#[tokio::test]
async fn signed_idle_timeout_is_refreshed_by_protocol_activity() {
    let (client_carrier, server_carrier) = memory_carrier_pair_for_logical(1);
    let client_config = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "signed-idle-timeout".into(),
        session_contract_hash: [0x75; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x76; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::from_millis(80),
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV2 {
            close_flush: Duration::from_millis(20),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");
    tokio::time::sleep(Duration::from_millis(50)).await;
    client
        .probe_liveness()
        .await
        .expect("protocol activity before idle deadline");
    tokio::time::sleep(Duration::from_millis(50)).await;
    client
        .probe_liveness()
        .await
        .expect("activity must refresh idle watchdog");
    let terminal = tokio::time::timeout(Duration::from_millis(500), client.wait_closed())
        .await
        .expect("idle watchdog did not terminate the session")
        .expect_err("idle watchdog must expose a terminal cause");
    assert_eq!(terminal.kind(), io::ErrorKind::TimedOut);
    assert!(client.probe_liveness().await.is_err());
    assert!(server.probe_liveness().await.is_err());
}

#[derive(Debug)]
struct CloseObservingCarrierSession {
    inner: Arc<dyn CarrierSessionV2>,
    closes: Arc<AtomicU64>,
}

#[derive(Debug)]
struct HangingCloseCarrierSession {
    inner: Arc<dyn CarrierSessionV2>,
    active_closes: Arc<AtomicU64>,
}

#[derive(Debug)]
struct ActiveCloseGuard(Arc<AtomicU64>);

impl Drop for ActiveCloseGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[async_trait::async_trait]
impl CarrierSessionV2 for HangingCloseCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        self.inner.accept_stream().await
    }

    async fn close(&self) -> io::Result<()> {
        self.active_closes.fetch_add(1, Ordering::AcqRel);
        let _guard = ActiveCloseGuard(self.active_closes.clone());
        std::future::pending().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV2 for CloseObservingCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>> {
        self.inner.accept_stream().await
    }

    async fn close(&self) -> io::Result<()> {
        self.closes.fetch_add(1, Ordering::AcqRel);
        self.inner.close().await
    }
}

fn regression_config(
    role: SessionRole,
    channel_id: &str,
    max_inbound_streams: u16,
    rpc_handler: Option<Arc<dyn RpcHandlerV2>>,
) -> SessionConfigV2 {
    let (local_admission_binding, peer_admission_binding) = match role {
        SessionRole::Client => ([1; 32], Some([2; 32])),
        SessionRole::Server => ([2; 32], Some([1; 32])),
    };
    SessionConfigV2 {
        role,
        path: PathKind::Direct,
        channel_id: channel_id.into(),
        session_contract_hash: [0x81; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x82; 32],
        max_inbound_streams,
        idle_timeout: Duration::ZERO,
        local_admission_binding,
        peer_admission_binding,
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler,
        deadlines: SessionDeadlinesV2 {
            establish: Duration::from_millis(20),
            rekey_prepare: Duration::from_millis(100),
            rekey_completion: Duration::from_millis(100),
            close_flush: Duration::from_millis(20),
        },
    }
}

#[tokio::test]
async fn direct_and_tunnel_endpoint_identity_shapes_fail_before_carrier_io() {
    let (direct_carrier, _direct_peer) = memory_carrier_pair_v2();
    let mut direct = regression_config(SessionRole::Client, "invalid-direct-endpoint", 1, None);
    direct.local_endpoint_instance_id = Some("must-not-exist".into());
    direct.expected_peer_endpoint_instance_id = Some("must-not-exist".into());
    let direct_error = establish_session_v2(direct_carrier, direct)
        .await
        .expect_err("direct endpoint identities must be absent");
    assert_eq!(direct_error.kind(), io::ErrorKind::InvalidData);

    let (tunnel_carrier, _tunnel_peer) = memory_carrier_pair_v2();
    let mut tunnel = regression_config(SessionRole::Client, "invalid-tunnel-endpoint", 1, None);
    tunnel.path = PathKind::Tunnel;
    tunnel.local_endpoint_instance_id = Some("endpoint-client".into());
    let tunnel_error = establish_session_v2(tunnel_carrier, tunnel)
        .await
        .expect_err("tunnel endpoint identities must both be present");
    assert_eq!(tunnel_error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn protocol_failure_closes_carrier_and_wakes_blocked_accept() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let injected_client_carrier = client_inner.clone();
    let closes = Arc::new(AtomicU64::new(0));
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(CloseObservingCarrierSession {
        inner: client_inner,
        closes: closes.clone(),
    });
    let (client, server) = tokio::join!(
        establish_session_v2(
            client_carrier,
            regression_config(SessionRole::Client, "failure-cleanup", 1, None),
        ),
        establish_session_v2(
            server_carrier.clone(),
            regression_config(SessionRole::Server, "failure-cleanup", 1, None),
        ),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");
    let accepting = {
        let client = client.clone();
        tokio::spawn(async move { client.accept_stream().await })
    };

    injected_client_carrier
        .close()
        .await
        .expect("inject local carrier failure");
    let error = tokio::time::timeout(Duration::from_millis(250), accepting)
        .await
        .expect("blocked accept was not woken by session failure")
        .expect("join blocked accept")
        .expect_err("accept after failure must fail");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    tokio::time::timeout(Duration::from_millis(250), async {
        while closes.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("protocol failure did not close the local carrier");
    let first_cause = client
        .wait_closed()
        .await
        .expect_err("terminated session must expose its cause");
    let repeated_cause = client
        .wait_closed()
        .await
        .expect_err("termination observation must be repeatable");
    assert_eq!(first_cause.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(repeated_cause.kind(), first_cause.kind());
    assert_eq!(repeated_cause.to_string(), first_cause.to_string());
    let _ = server.close().await;
}

#[tokio::test]
async fn stalled_fss2_does_not_block_later_authenticated_streams() {
    let (client_carrier, server_carrier) = memory_carrier_pair_for_logical(2);
    let raw_client_carrier = client_carrier.clone();
    let (client, server) = tokio::join!(
        establish_session_v2(
            client_carrier,
            regression_config(SessionRole::Client, "stalled-fss2", 2, None),
        ),
        establish_session_v2(
            server_carrier,
            regression_config(SessionRole::Server, "stalled-fss2", 2, None),
        ),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");

    let stalled = raw_client_carrier
        .open_stream()
        .await
        .expect("open carrier stream without FSS2");
    tokio::time::sleep(Duration::from_millis(10)).await;
    let (outgoing, incoming) = tokio::time::timeout(Duration::from_millis(250), async {
        tokio::join!(
            client.open_stream("after-stalled-fss2", serde_json::Map::new()),
            server.accept_stream(),
        )
    })
    .await
    .expect("stalled FSS2 caused session-level head-of-line blocking");
    assert_eq!(outgoing.expect("authenticated outgoing stream").id(), 1);
    assert_eq!(incoming.expect("authenticated incoming stream").id(), 1);
    stalled.reset().await.expect("reset stalled carrier stream");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn queued_data_open_does_not_starve_reserved_rpc_capacity() {
    let (client_carrier, server_carrier) = memory_carrier_pair_for_logical(1);
    let (client, server) = tokio::join!(
        establish_session_v2(
            client_carrier,
            regression_config(SessionRole::Client, "rpc-reserved-capacity", 1, None),
        ),
        establish_session_v2(
            server_carrier,
            regression_config(
                SessionRole::Server,
                "rpc-reserved-capacity",
                1,
                Some(Arc::new(EchoRpc)),
            ),
        ),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");
    let (first, first_incoming) = tokio::join!(
        client.open_stream("capacity-owner", serde_json::Map::new()),
        server.accept_stream(),
    );
    let first = first.expect("first data stream");
    let first_incoming = first_incoming.expect("first incoming data stream");
    let queued = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("queued-data", serde_json::Map::new())
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(10)).await;

    let response = tokio::time::timeout(
        Duration::from_millis(250),
        client.rpc().call(7, serde_json::json!({"reserved": true})),
    )
    .await
    .expect("queued data open starved reserved RPC")
    .expect("reserved RPC call");
    assert_eq!(response["request"]["reserved"], true);

    queued.abort();
    first.reset().await.expect("reset first data stream");
    first_incoming
        .stream()
        .reset()
        .await
        .expect("reset first incoming stream");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn peer_initiated_rekey_is_bounded_by_the_receivers_completion_deadline() {
    let (client_carrier, server_inner) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let server_carrier: Arc<dyn CarrierSessionV2> =
        Arc::new(BlockingApplicationReadCarrierSession {
            inner: server_inner,
            accepts: AtomicU64::new(0),
            block_on: 2,
            enabled: enabled.clone(),
            entered: entered.clone(),
            release: release.clone(),
        });
    let client_config = regression_config(SessionRole::Client, "peer-rekey-deadline", 1, None);
    let mut server_config = regression_config(SessionRole::Server, "peer-rekey-deadline", 1, None);
    server_config.deadlines.rekey_completion = Duration::from_millis(25);
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");
    let (stream, incoming) = tokio::join!(
        client.open_stream("peer-rekey-deadline", serde_json::Map::new()),
        server.accept_stream(),
    );
    let stream = stream.expect("outgoing stream");
    let incoming = incoming.expect("incoming stream");
    enabled.store(true, Ordering::Release);
    let rekeying = {
        let client = client.clone();
        tokio::spawn(async move { client.rekey().await })
    };
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("receiver never waited for the stream key update");
    let terminal = tokio::time::timeout(Duration::from_millis(250), server.wait_closed())
        .await
        .expect("peer-initiated rekey ignored the receiver completion deadline")
        .expect_err("receiver deadline must terminate the session");
    assert_eq!(terminal.kind(), io::ErrorKind::TimedOut);
    release.notify_waiters();
    assert!(rekeying.await.expect("join rekey task").is_err());
    let _ = stream.reset().await;
    let _ = incoming.stream().reset().await;
}

#[tokio::test]
async fn close_flush_deadline_also_bounds_carrier_close() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let active_closes = Arc::new(AtomicU64::new(0));
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(HangingCloseCarrierSession {
        inner: client_inner,
        active_closes: active_closes.clone(),
    });
    let mut client_config =
        regression_config(SessionRole::Client, "bounded-carrier-close", 1, None);
    let mut server_config =
        regression_config(SessionRole::Server, "bounded-carrier-close", 1, None);
    client_config.deadlines.close_flush = Duration::from_millis(20);
    server_config.deadlines.close_flush = Duration::from_millis(20);
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");

    let error = tokio::time::timeout(Duration::from_millis(250), client.close())
        .await
        .expect("carrier close escaped the close_flush deadline")
        .expect_err("hanging carrier close must report timeout");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(active_closes.load(Ordering::Acquire), 0);
    let _ = server.close().await;
}

#[tokio::test]
async fn idle_timeout_drops_a_hanging_carrier_close_future() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let active_closes = Arc::new(AtomicU64::new(0));
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(HangingCloseCarrierSession {
        inner: client_inner,
        active_closes: active_closes.clone(),
    });
    let mut client_config = regression_config(SessionRole::Client, "bounded-idle-close", 1, None);
    let server_config = regression_config(SessionRole::Server, "bounded-idle-close", 1, None);
    client_config.idle_timeout = Duration::from_millis(20);
    client_config.deadlines.close_flush = Duration::from_millis(20);
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");

    let error = tokio::time::timeout(Duration::from_millis(250), client.wait_closed())
        .await
        .expect("idle timeout did not terminate the session")
        .expect_err("idle timeout must expose a terminal cause");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(active_closes.load(Ordering::Acquire), 0);
    let _ = server.close().await;
}

#[tokio::test]
async fn local_rekey_waits_for_an_in_flight_inbound_open_responder() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV2> =
        Arc::new(BlockingApplicationReadCarrierSession {
            inner: client_inner,
            accepts: AtomicU64::new(0),
            block_on: 1,
            enabled: enabled.clone(),
            entered: entered.clone(),
            release: release.clone(),
        });
    let mut client_config = regression_config(SessionRole::Client, "inbound-open-rekey", 1, None);
    let mut server_config = regression_config(SessionRole::Server, "inbound-open-rekey", 1, None);
    client_config.deadlines.rekey_prepare = Duration::from_millis(500);
    client_config.deadlines.rekey_completion = Duration::from_millis(500);
    server_config.deadlines.rekey_prepare = Duration::from_millis(500);
    server_config.deadlines.rekey_completion = Duration::from_millis(500);
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");

    enabled.store(true, Ordering::Release);
    let opening = {
        let server = server.clone();
        tokio::spawn(async move {
            server
                .open_stream("concurrent-inbound-open", serde_json::Map::new())
                .await
        })
    };
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("inbound responder never reached the blocked FSS2 read");
    let rekeying = {
        let client = client.clone();
        tokio::spawn(async move { client.rekey().await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !rekeying.is_finished(),
        "rekey bypassed the inbound responder"
    );

    release.notify_waiters();
    let incoming = tokio::time::timeout(Duration::from_millis(750), client.accept_stream())
        .await
        .expect("inbound OPEN was not delivered")
        .expect("accept inbound stream");
    let outgoing = tokio::time::timeout(Duration::from_millis(750), opening)
        .await
        .expect("outbound OPEN never received its ACK")
        .expect("join outbound OPEN")
        .expect("open outbound stream");
    tokio::time::timeout(Duration::from_millis(750), rekeying)
        .await
        .expect("rekey did not complete after responder release")
        .expect("join rekey")
        .expect("complete rekey");
    outgoing
        .write(Bytes::from_static(b"after-responder-barrier"))
        .await
        .expect("write after responder barrier");
    assert_eq!(
        incoming.stream().read().await.expect("read after rekey"),
        Some(Bytes::from_static(b"after-responder-barrier"))
    );
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}
