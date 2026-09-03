use std::{
    io,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use crate::{
    protocol_v3::CipherSuiteV3,
    session_v3::{
        MAX_BUFFERED_STREAM_BYTES_V3, RpcHandlerV3, SessionConfigV3, SessionDeadlinesV3,
        establish_session_v3, memory_carrier_pair_v3, memory_carrier_pair_v3_with_capacities,
        memory_carrier_pair_v3_with_capacity,
    },
    transport_v3::{
        CarrierKind, CarrierSessionV3, CarrierStreamV3, CarrierUnreliableMessageErrorV3, PathKind,
        RpcCallError, RpcError, Session, SessionError, SessionRole, StreamMetadata,
        UnreliableMessageError,
    },
};
use bytes::Bytes;
use tokio::sync::{Mutex as TokioMutex, Notify, Semaphore, mpsc};

fn deterministic_test_bytes(seed: u8) -> [u8; 32] {
    std::array::from_fn(|index| seed ^ index as u8)
}

#[tokio::test]
async fn exact_handshake_and_ready_boundary_establish_a_memory_pair() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let psk = [0x42; 32];
    let contract = [0x24; 32];
    let client = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Tunnel,
        channel_id: "rust-session-v3".into(),
        session_contract_hash: contract,
        suite: CipherSuiteV3::ChaCha20Poly1305,
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
    let server = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        local_endpoint_instance_id: Some("server-instance".into()),
        expected_peer_endpoint_instance_id: Some("client-instance".into()),
        ..client.clone()
    };

    let (client_result, server_result) = tokio::join!(
        establish_session_v3(client_carrier, client),
        establish_session_v3(server_carrier, server),
    );
    let client: Arc<dyn Session> = client_result.expect("client session");
    let server: Arc<dyn Session> = server_result.expect("server session");
    assert_eq!(
        client.unreliable_messages().unwrap_err(),
        UnreliableMessageError::Unavailable,
        "a carrier without native DATAGRAM must remain explicitly unavailable"
    );
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn client_datagram_offer_with_unsupported_server_reaches_ready_without_unreliable_channel() {
    let (client_inner, server_carrier) = memory_carrier_pair_v3();
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedUnreliableCarrierSession {
        inner: client_inner,
        gate_sends: false,
        send_error: None,
        started: Arc::new(AtomicUsize::new(0)),
        started_notify: Arc::new(Notify::new()),
        release: Arc::new(Semaphore::new(0)),
    });
    let client = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rust-asymmetric-unreliable-feature".into(),
        session_contract_hash: [0x34; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [0x43; 32],
        max_inbound_streams: 4,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: Default::default(),
    };
    let server = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client.clone()
    };

    let (client_result, server_result) = tokio::join!(
        establish_session_v3(client_carrier, client),
        establish_session_v3(server_carrier, server),
    );
    let client = client_result.expect("client completes authenticated Finished");
    let server = server_result.expect("server verifies authenticated Finished");
    assert_eq!(
        client.unreliable_messages().unwrap_err(),
        UnreliableMessageError::Unavailable
    );
    assert_eq!(
        server.unreliable_messages().unwrap_err(),
        UnreliableMessageError::Unavailable
    );
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn unreliable_send_budget_drops_the_sixty_fifth_pending_send() {
    let (client_inner, server_inner) = memory_carrier_pair_v3_with_capacity(3);
    let started = Arc::new(AtomicUsize::new(0));
    let started_notify = Arc::new(Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedUnreliableCarrierSession {
        inner: client_inner,
        gate_sends: true,
        send_error: None,
        started: started.clone(),
        started_notify: started_notify.clone(),
        release: release.clone(),
    });
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedUnreliableCarrierSession {
        inner: server_inner,
        gate_sends: false,
        send_error: None,
        started: Arc::new(AtomicUsize::new(0)),
        started_notify: Arc::new(Notify::new()),
        release: Arc::new(Semaphore::new(0)),
    });
    let client_config = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rust-unreliable-budget".into(),
        session_contract_hash: [0x71; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [0x72; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: Default::default(),
    };
    let server_config = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("establish budget client");
    let server = server.expect("establish budget server");
    let mut pending = Vec::new();
    for value in 0_u8..64 {
        let client = client.clone();
        pending.push(tokio::spawn(async move {
            client
                .unreliable_messages()
                .expect("negotiated unreliable channel")
                .send(
                    Bytes::from(vec![value]),
                    SystemTime::now() + Duration::from_secs(30),
                )
                .await
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while started.load(Ordering::Acquire) != 64 {
            started_notify.notified().await;
        }
    })
    .await
    .expect("64 sends occupy the explicit pending budget");
    assert_eq!(
        client
            .unreliable_messages()
            .unwrap()
            .send(
                Bytes::from_static(b"sixty-fifth"),
                SystemTime::now() + Duration::from_secs(30),
            )
            .await,
        Ok(crate::UnreliableSendOutcome::DroppedBudget)
    );
    assert_eq!(started.load(Ordering::Acquire), 64);
    release.add_permits(64);
    for send in pending {
        assert_eq!(
            send.await.expect("join pending unreliable send"),
            Ok(crate::UnreliableSendOutcome::Accepted)
        );
    }
    client.close().await.expect("close budget client");
    server.close().await.expect("close budget server");
}

#[tokio::test]
async fn unreliable_carrier_drop_is_a_public_send_outcome() {
    let (client_inner, server_inner) = memory_carrier_pair_v3_with_capacity(3);
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedUnreliableCarrierSession {
        inner: client_inner,
        gate_sends: false,
        send_error: Some(CarrierUnreliableMessageErrorV3::Dropped),
        started: Arc::new(AtomicUsize::new(0)),
        started_notify: Arc::new(Notify::new()),
        release: Arc::new(Semaphore::new(0)),
    });
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedUnreliableCarrierSession {
        inner: server_inner,
        gate_sends: false,
        send_error: None,
        started: Arc::new(AtomicUsize::new(0)),
        started_notify: Arc::new(Notify::new()),
        release: Arc::new(Semaphore::new(0)),
    });
    let client_config = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rust-unreliable-carrier-drop".into(),
        session_contract_hash: [0x81; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [0x82; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: Default::default(),
    };
    let server_config = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("establish carrier-drop client");
    let server = server.expect("establish carrier-drop server");

    assert_eq!(
        client
            .unreliable_messages()
            .unwrap()
            .send(
                Bytes::from_static(b"dropped"),
                SystemTime::now() + Duration::from_secs(30),
            )
            .await,
        Ok(crate::UnreliableSendOutcome::DroppedCarrier)
    );

    client.close().await.expect("close carrier-drop client");
    server.close().await.expect("close carrier-drop server");
}

#[derive(Debug)]
struct GatedCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    gate: Arc<AtomicBool>,
    write_entered: Arc<Notify>,
    release_write: Arc<Notify>,
}

#[derive(Debug)]
struct GatedCarrierStream {
    inner: Arc<dyn CarrierStreamV3>,
    gate: Arc<AtomicBool>,
    write_entered: Arc<Notify>,
    release_write: Arc<Notify>,
}

#[derive(Debug)]
struct ShortWriteCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    enabled: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
    fragment_written: Arc<Notify>,
    release_write: Arc<Semaphore>,
}

#[derive(Debug)]
struct ShortWriteCarrierStream {
    inner: Arc<dyn CarrierStreamV3>,
    enabled: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
    fragment_written: Arc<Notify>,
    release_write: Arc<Semaphore>,
}

#[derive(Debug)]
struct FailingNthOpenCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    opens: AtomicU64,
    fail_on: u64,
}

#[derive(Debug)]
struct CapacityReportingCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    capacity: u32,
    opens: Arc<AtomicU64>,
}

#[derive(Debug)]
struct GatedUnreliableCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    gate_sends: bool,
    send_error: Option<CarrierUnreliableMessageErrorV3>,
    started: Arc<AtomicUsize>,
    started_notify: Arc<Notify>,
    release: Arc<Semaphore>,
}

#[derive(Debug)]
struct TestDatagramCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    outgoing: mpsc::UnboundedSender<Bytes>,
    incoming: TokioMutex<mpsc::UnboundedReceiver<Bytes>>,
    streams: AtomicU64,
    control_post_write_gate: Option<Arc<PostWriteGate>>,
}

#[derive(Debug)]
struct PostWriteGate {
    enabled: AtomicBool,
    writes: AtomicU64,
    block_on: u64,
    entered: Notify,
    release: Semaphore,
}

#[derive(Debug)]
struct PostWriteGatedCarrierStream {
    inner: Arc<dyn CarrierStreamV3>,
    gate: Arc<PostWriteGate>,
}

impl TestDatagramCarrierSession {
    fn wrap_control(&self, stream: Arc<dyn CarrierStreamV3>) -> Arc<dyn CarrierStreamV3> {
        if self.streams.fetch_add(1, Ordering::AcqRel) == 0
            && let Some(gate) = &self.control_post_write_gate
        {
            return Arc::new(PostWriteGatedCarrierStream {
                inner: stream,
                gate: gate.clone(),
            });
        }
        stream
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for TestDatagramCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(self.wrap_control(self.inner.open_stream().await?))
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(self.wrap_control(self.inner.accept_stream().await?))
    }

    fn unreliable_message_max_size(&self) -> Option<usize> {
        Some(65_535)
    }

    async fn send_unreliable_message(
        &self,
        payload: Bytes,
    ) -> Result<(), CarrierUnreliableMessageErrorV3> {
        self.outgoing
            .send(payload)
            .map_err(|_| CarrierUnreliableMessageErrorV3::Closed)
    }

    async fn receive_unreliable_message(&self) -> Result<Bytes, CarrierUnreliableMessageErrorV3> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or(CarrierUnreliableMessageErrorV3::Closed)
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierStreamV3 for PostWriteGatedCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner.read(payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(payload).await?;
        if self.gate.enabled.load(Ordering::Acquire) {
            let ordinal = self.gate.writes.fetch_add(1, Ordering::AcqRel) + 1;
            if ordinal == self.gate.block_on {
                self.gate.entered.notify_one();
                self.gate
                    .release
                    .acquire()
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "write gate closed"))?
                    .forget();
            }
        }
        Ok(written)
    }

    async fn close_write(&self) -> io::Result<()> {
        self.inner.close_write().await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await
    }

    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for GatedUnreliableCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.accept_stream().await
    }

    fn unreliable_message_max_size(&self) -> Option<usize> {
        Some(1_024)
    }

    async fn send_unreliable_message(
        &self,
        _payload: Bytes,
    ) -> Result<(), CarrierUnreliableMessageErrorV3> {
        if let Some(error) = self.send_error {
            return Err(error);
        }
        if self.gate_sends {
            self.started.fetch_add(1, Ordering::AcqRel);
            self.started_notify.notify_waiters();
            let permit = self
                .release
                .acquire()
                .await
                .map_err(|_| CarrierUnreliableMessageErrorV3::Closed)?;
            permit.forget();
        }
        Ok(())
    }

    async fn receive_unreliable_message(&self) -> Result<Bytes, CarrierUnreliableMessageErrorV3> {
        std::future::pending().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for CapacityReportingCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.capacity
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.opens.fetch_add(1, Ordering::AcqRel);
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.accept_stream().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for FailingNthOpenCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }
    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        let ordinal = self.opens.fetch_add(1, Ordering::AcqRel) + 1;
        if ordinal == self.fail_on {
            return Err(io::Error::other("injected carrier open failure"));
        }
        self.inner.open_stream().await
    }
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.accept_stream().await
    }
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

#[derive(Debug)]
struct BlockingNthWriteCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    enabled: Arc<AtomicBool>,
    writes: Arc<AtomicU64>,
    block_on: u64,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[derive(Debug)]
struct BlockingNthWriteCarrierStream {
    inner: Arc<dyn CarrierStreamV3>,
    enabled: Arc<AtomicBool>,
    writes: Arc<AtomicU64>,
    block_on: u64,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[derive(Debug)]
struct FailingControlWriteCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    opens: AtomicU64,
    fail_next_control_write: Arc<AtomicBool>,
    application_reset_entered: Arc<AtomicU64>,
    application_resets: Arc<AtomicU64>,
}

#[derive(Debug)]
struct FailingControlWriteCarrierStream {
    inner: Arc<dyn CarrierStreamV3>,
    fail_next_write: Arc<AtomicBool>,
}

#[derive(Debug)]
struct ResetCountingCarrierStream {
    inner: Arc<dyn CarrierStreamV3>,
    reset_entered: Arc<AtomicU64>,
    resets: Arc<AtomicU64>,
}

#[derive(Debug)]
struct BlockingApplicationReadCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    accepts: AtomicU64,
    block_on: u64,
    enabled: Arc<AtomicBool>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[derive(Debug)]
struct BlockingApplicationReadCarrierStream {
    inner: Arc<dyn CarrierStreamV3>,
    enabled: Arc<AtomicBool>,
    blocked: AtomicBool,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[derive(Debug)]
struct ControlFlushOrderCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    next_order: Arc<AtomicU64>,
    control_finish_order: Arc<AtomicU64>,
    carrier_close_order: Arc<AtomicU64>,
}

#[derive(Debug)]
struct ControlFlushOrderCarrierStream {
    inner: Arc<dyn CarrierStreamV3>,
    next_order: Arc<AtomicU64>,
    control_finish_order: Arc<AtomicU64>,
}

#[derive(Debug)]
struct ResetAfterFinCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    accepts: AtomicU64,
    close_writes: Arc<AtomicU64>,
    resets: Arc<AtomicU64>,
    reset_entered: Option<Arc<Notify>>,
    reset_release: Option<Arc<Semaphore>>,
}

#[derive(Debug)]
struct ResetAfterFinCarrierStream {
    inner: Arc<dyn CarrierStreamV3>,
    close_writes: Arc<AtomicU64>,
    resets: Arc<AtomicU64>,
    reset_entered: Option<Arc<Notify>>,
    reset_release: Option<Arc<Semaphore>>,
}

#[async_trait::async_trait]
impl CarrierSessionV3 for ResetAfterFinCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        let stream = self.inner.accept_stream().await?;
        if self.accepts.fetch_add(1, Ordering::AcqRel) + 1 == 2 {
            Ok(Arc::new(ResetAfterFinCarrierStream {
                inner: stream,
                close_writes: self.close_writes.clone(),
                resets: self.resets.clone(),
                reset_entered: self.reset_entered.clone(),
                reset_release: self.reset_release.clone(),
            }))
        } else {
            Ok(stream)
        }
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierStreamV3 for ResetAfterFinCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner.read(payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        self.inner.write(payload).await
    }

    async fn close_write(&self) -> io::Result<()> {
        self.close_writes.fetch_add(1, Ordering::AcqRel);
        self.inner.close_write().await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await
    }

    async fn reset(&self) -> io::Result<()> {
        let reset_ordinal = self.resets.fetch_add(1, Ordering::AcqRel);
        if reset_ordinal == 0 {
            if let Some(entered) = &self.reset_entered {
                entered.notify_one();
            }
            if let Some(release) = &self.reset_release {
                release.acquire().await.expect("reset gate closed").forget();
            }
        }
        self.inner.reset().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for ControlFlushOrderCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(Arc::new(ControlFlushOrderCarrierStream {
            inner: self.inner.open_stream().await?,
            next_order: self.next_order.clone(),
            control_finish_order: self.control_finish_order.clone(),
        }))
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.accept_stream().await
    }

    async fn close(&self) -> io::Result<()> {
        self.carrier_close_order.store(
            self.next_order.fetch_add(1, Ordering::AcqRel) + 1,
            Ordering::Release,
        );
        self.inner.close().await
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierStreamV3 for ControlFlushOrderCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner.read(payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        self.inner.write(payload).await
    }

    async fn close_write(&self) -> io::Result<()> {
        self.control_finish_order.store(
            self.next_order.fetch_add(1, Ordering::AcqRel) + 1,
            Ordering::Release,
        );
        self.inner.close_write().await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await
    }

    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for BlockingApplicationReadCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
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

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierStreamV3 for BlockingApplicationReadCarrierStream {
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

    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await
    }

    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for BlockingNthWriteCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }
    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(Arc::new(BlockingNthWriteCarrierStream {
            inner: self.inner.open_stream().await?,
            enabled: self.enabled.clone(),
            writes: self.writes.clone(),
            block_on: self.block_on,
            entered: self.entered.clone(),
            release: self.release.clone(),
        }))
    }
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
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

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierStreamV3 for BlockingNthWriteCarrierStream {
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
    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await
    }
    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await
    }
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for FailingControlWriteCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        let stream = self.inner.open_stream().await?;
        if self.opens.fetch_add(1, Ordering::AcqRel) == 0 {
            Ok(Arc::new(FailingControlWriteCarrierStream {
                inner: stream,
                fail_next_write: self.fail_next_control_write.clone(),
            }))
        } else {
            Ok(Arc::new(ResetCountingCarrierStream {
                inner: stream,
                reset_entered: self.application_reset_entered.clone(),
                resets: self.application_resets.clone(),
            }))
        }
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.accept_stream().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierStreamV3 for FailingControlWriteCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner.read(payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        if self.fail_next_write.swap(false, Ordering::AcqRel) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected control write failure",
            ));
        }
        self.inner.write(payload).await
    }

    async fn close_write(&self) -> io::Result<()> {
        self.inner.close_write().await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await
    }

    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierStreamV3 for ResetCountingCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner.read(payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        self.inner.write(payload).await
    }

    async fn close_write(&self) -> io::Result<()> {
        self.inner.close_write().await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await
    }

    async fn reset(&self) -> io::Result<()> {
        self.reset_entered.fetch_add(1, Ordering::AcqRel);
        self.inner.reset().await?;
        self.resets.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for GatedCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }
    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(Arc::new(GatedCarrierStream {
            inner: self.inner.open_stream().await?,
            gate: self.gate.clone(),
            write_entered: self.write_entered.clone(),
            release_write: self.release_write.clone(),
        }))
    }
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
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

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierStreamV3 for GatedCarrierStream {
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
    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await
    }
    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await
    }
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for ShortWriteCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(Arc::new(ShortWriteCarrierStream {
            inner: self.inner.open_stream().await?,
            enabled: self.enabled.clone(),
            writes: self.writes.clone(),
            fragment_written: self.fragment_written.clone(),
            release_write: self.release_write.clone(),
        }))
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(Arc::new(ShortWriteCarrierStream {
            inner: self.inner.accept_stream().await?,
            enabled: self.enabled.clone(),
            writes: self.writes.clone(),
            fragment_written: self.fragment_written.clone(),
            release_write: self.release_write.clone(),
        }))
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierStreamV3 for ShortWriteCarrierStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner.read(payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        if !self.enabled.load(Ordering::Acquire) {
            return self.inner.write(payload).await;
        }
        let written = self.inner.write(&payload[..payload.len().min(3)]).await?;
        if self.writes.fetch_add(1, Ordering::AcqRel) == 0 {
            self.fragment_written.notify_one();
            self.release_write.acquire().await.unwrap().forget();
        }
        Ok(written)
    }

    async fn close_write(&self) -> io::Result<()> {
        self.inner.close_write().await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await
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
impl RpcHandlerV3 for EchoRpc {
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        Ok(serde_json::json!({"type_id": type_id, "request": request}))
    }
    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        Ok(())
    }
}

#[derive(Debug)]
struct GatedFirstRpc {
    calls: AtomicUsize,
    first_started: Arc<Notify>,
    release_first: Arc<Semaphore>,
}

#[derive(Debug)]
struct CountingNotifyRpc {
    notifications: Arc<AtomicUsize>,
    delivered: Arc<Notify>,
}

#[async_trait::async_trait]
impl RpcHandlerV3 for CountingNotifyRpc {
    async fn call(
        &self,
        _type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        Ok(request)
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        self.notifications.fetch_add(1, Ordering::AcqRel);
        self.delivered.notify_one();
        Ok(())
    }
}

#[async_trait::async_trait]
impl RpcHandlerV3 for GatedFirstRpc {
    async fn call(
        &self,
        _type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        if self.calls.fetch_add(1, Ordering::AcqRel) == 0 {
            self.first_started.notify_one();
            self.release_first.acquire().await.unwrap().forget();
        }
        Ok(request)
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        Ok(())
    }
}

#[tokio::test]
async fn canceled_rpc_late_response_does_not_poison_next_call() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let first_started = Arc::new(Notify::new());
    let release_first = Arc::new(Semaphore::new(0));
    let handler = Arc::new(GatedFirstRpc {
        calls: AtomicUsize::new(0),
        first_started: first_started.clone(),
        release_first: release_first.clone(),
    });
    let client_config = regression_config(SessionRole::Client, "rpc-caller-drop", 4, None);
    let server_config = regression_config(
        SessionRole::Server,
        "rpc-caller-drop",
        4,
        Some(handler.clone()),
    );
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");

    let first = {
        let client = client.clone();
        tokio::spawn(async move { client.rpc().call(1, serde_json::json!({"call": 1})).await })
    };
    first_started.notified().await;
    first.abort();
    let second = {
        let client = client.clone();
        tokio::spawn(async move { client.rpc().call(1, serde_json::json!({"call": 2})).await })
    };
    tokio::task::yield_now().await;
    assert_eq!(
        handler.calls.load(Ordering::Acquire),
        1,
        "call-2 crossed serial ownership before response-1 drained"
    );
    release_first.add_permits(1);

    let response = tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("call-2 remained blocked")
        .expect("call-2 task")
        .expect("late response poisoned call-2");
    assert_eq!(response, serde_json::json!({"call": 2}));
    assert_eq!(handler.calls.load(Ordering::Acquire), 2);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn canceled_rpc_completes_a_partially_written_frame() {
    let (client_inner, server_carrier) = memory_carrier_pair_v3();
    let enabled = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicUsize::new(0));
    let fragment_written = Arc::new(Notify::new());
    let release_write = Arc::new(Semaphore::new(0));
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(ShortWriteCarrierSession {
        inner: client_inner,
        enabled: enabled.clone(),
        writes: writes.clone(),
        fragment_written: fragment_written.clone(),
        release_write: release_write.clone(),
    });
    let client_config = regression_config(SessionRole::Client, "rpc-partial-drop", 4, None);
    let server_config = regression_config(
        SessionRole::Server,
        "rpc-partial-drop",
        4,
        Some(Arc::new(EchoRpc)),
    );
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    client
        .rpc()
        .call(1, serde_json::json!({"warmup": true}))
        .await
        .expect("warm up reserved RPC stream");

    enabled.store(true, Ordering::Release);
    let canceled = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .rpc()
                .call(2, serde_json::json!({"payload": "x".repeat(256)}))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), fragment_written.notified())
        .await
        .expect("RPC frame never wrote its first short fragment");
    canceled.abort();
    release_write.add_permits(1);

    let response = tokio::time::timeout(
        Duration::from_secs(1),
        client
            .rpc()
            .call(3, serde_json::json!({"after": "partial-drop"})),
    )
    .await
    .expect("next RPC remained blocked")
    .expect("partial frame poisoned the RPC stream");
    assert_eq!(response["request"]["after"], "partial-drop");
    assert!(writes.load(Ordering::Acquire) > 1);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn canceled_rpc_notify_completes_a_partially_written_frame() {
    let (client_inner, server_carrier) = memory_carrier_pair_v3();
    let enabled = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicUsize::new(0));
    let fragment_written = Arc::new(Notify::new());
    let release_write = Arc::new(Semaphore::new(0));
    let notifications = Arc::new(AtomicUsize::new(0));
    let delivered = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(ShortWriteCarrierSession {
        inner: client_inner,
        enabled: enabled.clone(),
        writes: writes.clone(),
        fragment_written: fragment_written.clone(),
        release_write: release_write.clone(),
    });
    let client_config = regression_config(SessionRole::Client, "rpc-notify-partial-drop", 4, None);
    let server_config = regression_config(
        SessionRole::Server,
        "rpc-notify-partial-drop",
        4,
        Some(Arc::new(CountingNotifyRpc {
            notifications: notifications.clone(),
            delivered: delivered.clone(),
        })),
    );
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    client
        .rpc()
        .call(1, serde_json::json!({"warmup": true}))
        .await
        .expect("warm up reserved RPC stream");

    enabled.store(true, Ordering::Release);
    let canceled = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .rpc()
                .notify(2, serde_json::json!({"payload": "x".repeat(256)}))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), fragment_written.notified())
        .await
        .expect("RPC notify frame never wrote its first short fragment");
    canceled.abort();
    release_write.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), delivered.notified())
        .await
        .expect("dropped notify was not completed by the owned operation");
    assert_eq!(notifications.load(Ordering::Acquire), 1);

    let response = client
        .rpc()
        .call(3, serde_json::json!({"after": "notify-drop"}))
        .await
        .expect("partial notify poisoned the RPC stream");
    assert_eq!(response["after"], "notify-drop");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn rpc_dropped_before_serial_ownership_sends_no_request() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let first_started = Arc::new(Notify::new());
    let release_first = Arc::new(Semaphore::new(0));
    let handler = Arc::new(GatedFirstRpc {
        calls: AtomicUsize::new(0),
        first_started: first_started.clone(),
        release_first: release_first.clone(),
    });
    let client_config = regression_config(SessionRole::Client, "rpc-pre-serial-drop", 4, None);
    let server_config = regression_config(
        SessionRole::Server,
        "rpc-pre-serial-drop",
        4,
        Some(handler.clone()),
    );
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let first = {
        let client = client.clone();
        tokio::spawn(async move { client.rpc().call(1, serde_json::json!({"call": 1})).await })
    };
    first_started.notified().await;
    let waiting = {
        let client = client.clone();
        tokio::spawn(async move { client.rpc().call(1, serde_json::json!({"call": 2})).await })
    };
    tokio::task::yield_now().await;
    waiting.abort();
    release_first.add_permits(1);
    first.await.expect("first task").expect("first response");
    tokio::task::yield_now().await;
    assert_eq!(handler.calls.load(Ordering::Acquire), 1);

    let response = client
        .rpc()
        .call(1, serde_json::json!({"call": 3}))
        .await
        .expect("third response");
    assert_eq!(response["call"], 3);
    assert_eq!(handler.calls.load(Ordering::Acquire), 2);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn session_close_terminates_and_waits_for_an_owned_rpc_operation() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let first_started = Arc::new(Notify::new());
    let release_first = Arc::new(Semaphore::new(0));
    let handler = Arc::new(GatedFirstRpc {
        calls: AtomicUsize::new(0),
        first_started: first_started.clone(),
        release_first: release_first.clone(),
    });
    let client_config = regression_config(SessionRole::Client, "rpc-close-owned", 4, None);
    let server_config = regression_config(SessionRole::Server, "rpc-close-owned", 4, Some(handler));
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let calling = {
        let client = client.clone();
        tokio::spawn(async move { client.rpc().call(1, serde_json::json!({"call": 1})).await })
    };
    first_started.notified().await;
    tokio::time::timeout(Duration::from_secs(1), client.close())
        .await
        .expect("Session close did not wait for and terminate the active RPC operation")
        .expect("close client");
    assert!(calling.await.expect("RPC task").is_err());
    release_first.add_permits(1);
    server.close().await.expect("close server");
}

#[tokio::test]
async fn lazy_reserved_rpc_is_encrypted_and_uses_u32_type_ids() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let client = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rpc-v3".into(),
        session_contract_hash: [3; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
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
    let server = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        rpc_handler: Some(Arc::new(EchoRpc)),
        ..client.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client),
        establish_session_v3(server_carrier, server),
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

#[tokio::test]
async fn peer_rekey_completes_while_the_reserved_rpc_reader_is_idle() {
    let (client, server) = establish_pair().await;
    let response = client
        .rpc()
        .call(7, serde_json::json!({"open": "rpc-stream"}))
        .await
        .expect("open reserved RPC stream");
    assert_eq!(response["request"]["open"], "rpc-stream");

    tokio::time::timeout(Duration::from_secs(1), client.rekey())
        .await
        .expect("peer rekey deadlocked behind the idle RPC reader")
        .expect("peer rekey");
    let after = client
        .rpc()
        .call(8, serde_json::json!({"epoch": 1}))
        .await
        .expect("RPC after peer rekey");
    assert_eq!(after["request"]["epoch"], 1);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn peer_notifications_dispatch_subscriptions_without_owning_the_session() {
    let (client, server) = establish_pair().await;
    let delivered = Arc::new(AtomicUsize::new(0));
    let duplicate_delivered = Arc::new(AtomicUsize::new(0));
    let delivered_notify = Arc::new(Notify::new());
    let retained_resource = Arc::new(());
    let first_count = delivered.clone();
    let first_notify = delivered_notify.clone();
    let first = server
        .rpc()
        .subscribe_notification(
            27,
            Arc::new(move |payload| {
                assert_eq!(payload["sequence"], 1);
                first_count.fetch_add(1, Ordering::AcqRel);
                first_notify.notify_waiters();
            }),
        )
        .expect("first notification subscription");
    let duplicate_count = duplicate_delivered.clone();
    let duplicate = server
        .rpc()
        .subscribe_notification(
            27,
            Arc::new(move |payload| {
                assert_eq!(payload["sequence"], 1);
                duplicate_count.fetch_add(1, Ordering::AcqRel);
            }),
        )
        .expect("duplicate notification subscription");
    let panic_subscription = server
        .rpc()
        .subscribe_notification(27, Arc::new(|_| panic!("isolated subscriber panic")))
        .expect("panicking notification subscription");
    let handler_resource = retained_resource.clone();
    let close_resource_subscription = server
        .rpc()
        .subscribe_notification(
            29,
            Arc::new(move |_| {
                let _ = &handler_resource;
            }),
        )
        .expect("session-owned notification subscription");
    assert_eq!(Arc::strong_count(&retained_resource), 2);

    client
        .rpc()
        .notify(27, serde_json::json!({"sequence": 1}))
        .await
        .expect("send peer notification");
    tokio::time::timeout(Duration::from_secs(1), async {
        while delivered.load(Ordering::Acquire) != 1 {
            delivered_notify.notified().await;
        }
    })
    .await
    .expect("notification delivered");
    assert_eq!(duplicate_delivered.load(Ordering::Acquire), 1);

    panic_subscription.cancel();
    panic_subscription.cancel();
    duplicate.cancel();
    duplicate.cancel();
    first.cancel();
    first.cancel();
    client
        .rpc()
        .notify(27, serde_json::json!({"sequence": 2}))
        .await
        .expect("send notification after cancellation");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(delivered.load(Ordering::Acquire), 1);

    let response = client
        .rpc()
        .call(28, serde_json::json!({"after": "notification"}))
        .await
        .expect("subscriber panic and cancellation do not close RPC");
    assert_eq!(response["request"]["after"], "notification");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&retained_resource) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("session close releases notification handler resources");
    close_resource_subscription.cancel();
    close_resource_subscription.cancel();
}

#[tokio::test]
async fn peer_notifications_consume_every_shared_v3_payload_vector() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v3/rpc_notification_vectors.json"
    ))
    .expect("parse v3 notification vectors");
    assert_eq!(fixture["transport_contract_version"], 3);
    let type_id = fixture["type_id"].as_u64().expect("notification type ID") as u32;
    let scenarios = fixture["subscription_scenarios"]
        .as_array()
        .expect("notification scenarios");
    assert_eq!(scenarios.len(), 4);

    let (client, server) = establish_pair().await;
    for vector in fixture["payloads"]
        .as_array()
        .expect("notification payloads")
    {
        let id = vector["id"].as_str().expect("notification vector ID");
        let payload: serde_json::Value =
            serde_json::from_str(vector["json"].as_str().expect("notification vector JSON"))
                .unwrap_or_else(|error| panic!("{id}: parse payload: {error}"));
        let observed = Arc::new(StdMutex::new(Vec::new()));
        let delivered = Arc::new(Notify::new());
        let handler_observed = Arc::clone(&observed);
        let handler_delivered = Arc::clone(&delivered);
        let subscription = server
            .rpc()
            .subscribe_notification(
                type_id,
                Arc::new(move |value| {
                    handler_observed
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(value);
                    handler_delivered.notify_waiters();
                }),
            )
            .unwrap_or_else(|error| panic!("{id}: subscribe: {error}"));

        client
            .rpc()
            .notify(type_id, payload.clone())
            .await
            .unwrap_or_else(|error| panic!("{id}: notify: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !observed
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_empty()
                {
                    break;
                }
                delivered.notified().await;
            }
        })
        .await
        .unwrap_or_else(|error| panic!("{id}: delivery timeout: {error}"));
        assert_eq!(
            *observed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![payload],
            "{id}"
        );
        subscription.cancel();
    }
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn remote_rpc_application_error_preserves_bounded_semantics() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let client = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rpc-error-v3".into(),
        session_contract_hash: [31; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [32; 32],
        max_inbound_streams: 4,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [33; 32],
        peer_admission_binding: Some([34; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: Default::default(),
    };
    let server = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [34; 32],
        peer_admission_binding: Some([33; 32]),
        ..client.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client),
        establish_session_v3(server_carrier, server),
    );
    let client = client.expect("client");
    let server = server.expect("server");

    let error = client
        .rpc()
        .call(404, serde_json::json!({"lookup": "missing"}))
        .await
        .expect_err("missing handler must remain an application error");
    match error {
        RpcCallError::Application(error) => {
            assert_eq!(error.code(), 404);
            assert_eq!(error.message(), Some("handler not found"));
            assert_eq!(
                error.to_string(),
                "Flowersec RPC application error (code=404)"
            );
        }
        RpcCallError::Session(error) => panic!("application error collapsed into {error:?}"),
    }

    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[derive(Debug)]
struct WireBoundaryRpcFailure;

#[async_trait::async_trait]
impl RpcHandlerV3 for WireBoundaryRpcFailure {
    async fn call(
        &self,
        type_id: u32,
        _request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        let error = match type_id {
            1 => RpcError {
                code: 0,
                message: None,
            },
            2 => RpcError {
                code: 7,
                message: Some("a".repeat(1_024)),
            },
            3 => RpcError {
                code: 7,
                message: Some("a".repeat(1_025)),
            },
            4 => RpcError {
                code: 7,
                message: Some("é".repeat(512)),
            },
            5 => RpcError {
                code: 7,
                message: Some(format!("{}a", "é".repeat(512))),
            },
            6 => RpcError {
                code: 7,
                message: None,
            },
            _ => unreachable!("unexpected RPC invariant case"),
        };
        Err(error)
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        Ok(())
    }
}

#[tokio::test]
async fn rpc_outbound_handler_errors_are_sanitized_before_wire() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let client_config = regression_config(SessionRole::Client, "rpc-wire-error", 4, None);
    let server_config = regression_config(
        SessionRole::Server,
        "rpc-wire-error",
        4,
        Some(Arc::new(WireBoundaryRpcFailure)),
    );
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client");
    let server = server.expect("server");

    for (type_id, expected_message) in [
        (2, Some("a".repeat(1_024))),
        (4, Some("é".repeat(512))),
        (6, None),
    ] {
        match client.rpc().call(type_id, serde_json::Value::Null).await {
            Err(RpcCallError::Application(error)) => {
                assert_eq!(error.code(), 7);
                assert_eq!(error.message(), expected_message.as_deref());
            }
            result => panic!("valid handler error was not preserved: {result:?}"),
        }
    }
    for type_id in [1, 3, 5] {
        match client.rpc().call(type_id, serde_json::Value::Null).await {
            Err(RpcCallError::Application(error)) => {
                assert_eq!(error.code(), 500);
                assert_eq!(error.message(), Some("handler failed"));
            }
            result => panic!("invalid handler error was not sanitized: {result:?}"),
        }
    }

    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[derive(Debug)]
struct SensitiveRpcFailure;

#[async_trait::async_trait]
impl RpcHandlerV3 for SensitiveRpcFailure {
    async fn call(
        &self,
        _type_id: u32,
        _request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        Err(RpcError::new(500, Some("handler failed".into())).expect("valid RPC error"))
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        Ok(())
    }
}

#[tokio::test]
async fn rpc_handler_failure_is_sanitized_before_crossing_the_session() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let client = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rpc-redaction-v3".into(),
        session_contract_hash: [41; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [42; 32],
        max_inbound_streams: 4,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [43; 32],
        peer_admission_binding: Some([44; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: Default::default(),
    };
    let server = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [44; 32],
        peer_admission_binding: Some([43; 32]),
        rpc_handler: Some(Arc::new(SensitiveRpcFailure)),
        ..client.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client),
        establish_session_v3(server_carrier, server),
    );
    let client = client.expect("client");
    let server = server.expect("server");

    let error = client
        .rpc()
        .call(500, serde_json::Value::Null)
        .await
        .expect_err("handler failure");
    match error {
        RpcCallError::Application(error) => {
            assert_eq!(error.code(), 500);
            assert_eq!(error.message(), Some("handler failed"));
        }
        RpcCallError::Session(error) => panic!("application error collapsed into {error:?}"),
    }

    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

struct PanickingRpcHandler;

#[async_trait::async_trait]
impl RpcHandlerV3 for PanickingRpcHandler {
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        if type_id == 500 {
            panic!("application handler panic");
        }
        Ok(request)
    }

    async fn notify(&self, type_id: u32, _request: serde_json::Value) -> Result<(), RpcError> {
        if type_id == 501 {
            panic!("application notification handler panic");
        }
        Ok(())
    }
}

#[tokio::test]
async fn rpc_handler_panics_are_isolated_from_the_reserved_stream() {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let client = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rpc-panic-isolation".into(),
        session_contract_hash: [51; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [52; 32],
        max_inbound_streams: 4,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [53; 32],
        peer_admission_binding: Some([54; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: Default::default(),
    };
    let server = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [54; 32],
        peer_admission_binding: Some([53; 32]),
        rpc_handler: Some(Arc::new(PanickingRpcHandler)),
        ..client.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client),
        establish_session_v3(server_carrier, server),
    );
    let client = client.expect("client");
    let server = server.expect("server");

    let failure = tokio::time::timeout(
        Duration::from_secs(1),
        client.rpc().call(500, serde_json::Value::Null),
    )
    .await
    .expect("panicking RPC handler must produce a bounded response")
    .expect_err("panicking RPC handler must fail only its request");
    assert!(matches!(failure, RpcCallError::Application(_)));

    client
        .rpc()
        .notify(501, serde_json::Value::Null)
        .await
        .expect("send panicking notification");
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        client
            .rpc()
            .call(502, serde_json::json!({"after": "panic"})),
    )
    .await
    .expect("reserved RPC stream remains live")
    .expect("subsequent RPC succeeds");
    assert_eq!(response["after"], "panic");

    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

async fn establish_pair() -> (Arc<dyn Session>, Arc<dyn Session>) {
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let client = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "rust-session-streams".into(),
        session_contract_hash: [7; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
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
    let server = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client),
        establish_session_v3(server_carrier, server),
    );
    (client.expect("client"), server.expect("server"))
}

#[tokio::test]
async fn physical_capacity_mismatch_fails_before_control_stream_open() {
    let (inner, _peer) = memory_carrier_pair_v3();
    let opens = Arc::new(AtomicU64::new(0));
    let carrier: Arc<dyn CarrierSessionV3> = Arc::new(CapacityReportingCarrierSession {
        inner,
        capacity: 4,
        opens: opens.clone(),
    });
    let error = establish_session_v3(
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
) -> (Arc<dyn CarrierSessionV3>, Arc<dyn CarrierSessionV3>) {
    memory_carrier_pair_v3_with_capacity(u32::from(logical) + 2)
}

#[tokio::test]
async fn bidirectional_open_data_fin_and_consecutive_rekey() {
    let (client, server) = establish_pair().await;
    assert_eq!(format!("{client:?}"), "EncryptedSessionV3 { <opaque> }");
    assert_eq!(format!("{server:?}"), "EncryptedSessionV3 { <opaque> }");
    let (opened, incoming) = tokio::join!(
        client.open_stream("echo", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let opened = opened.expect("open");
    let incoming = incoming.expect("accept");
    assert_eq!(opened.internal_test_id(), 1);
    assert_eq!(incoming.internal_test_id(), 1);
    assert_eq!(format!("{opened:?}"), "EncryptedStreamV3 { <opaque> }");
    assert_eq!(
        format!("{:?}", incoming.stream()),
        "EncryptedStreamV3 { <opaque> }"
    );

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
    assert_eq!(
        incoming.stream().read().await.expect("repeat peer FIN"),
        None
    );
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn rekey_receive_buffer_applies_backpressure_and_preserves_order() {
    let (client_carrier, server_carrier) =
        memory_carrier_pair_v3_with_capacities(3, 8 * 1024 * 1024);
    let mut client_config = regression_config(SessionRole::Client, "bounded-rekey-buffer", 1, None);
    let mut server_config = regression_config(SessionRole::Server, "bounded-rekey-buffer", 1, None);
    client_config.deadlines.establish = Duration::from_secs(1);
    server_config.deadlines.establish = Duration::from_secs(1);
    client_config.deadlines.rekey_completion = Duration::from_secs(3);
    server_config.deadlines.rekey_completion = Duration::from_secs(3);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("bounded-rekey-buffer", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let outgoing = outgoing.expect("open stream");
    let incoming = incoming.expect("accept stream");
    let total = MAX_BUFFERED_STREAM_BYTES_V3 + 16 * 1024;
    let payload = Bytes::from(
        (0..total)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let mut offset = 0;
    while offset < payload.len() {
        offset += outgoing
            .write(payload.slice(offset..))
            .await
            .expect("write pre-rekey data");
    }

    let mut rekeying = {
        let client = client.clone();
        tokio::spawn(async move { client.rekey().await })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if incoming.stream().internal_test_buffered_bytes() == MAX_BUFFERED_STREAM_BYTES_V3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rekey helper did not reach the receive high-water mark");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut rekeying)
            .await
            .is_err(),
        "rekey crossed unread DATA instead of applying backpressure"
    );
    let mut received = Vec::with_capacity(total);
    while received.len() < total {
        let chunk = incoming
            .stream()
            .read()
            .await
            .expect("read buffered data")
            .expect("DATA before FIN");
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received, payload.as_ref());
    rekeying
        .await
        .expect("join rekey")
        .expect("rekey resumes after application reads");
    outgoing
        .write(Bytes::from_static(b"after-bounded-rekey"))
        .await
        .expect("post-rekey write");
    assert_eq!(
        incoming.stream().read().await.expect("post-rekey read"),
        Some(Bytes::from_static(b"after-bounded-rekey"))
    );
    outgoing.reset().await.expect("reset stream");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn reset_wakes_full_rekey_buffer_and_releases_capacity_once() {
    let (client_carrier, server_carrier) =
        memory_carrier_pair_v3_with_capacities(3, 8 * 1024 * 1024);
    let mut client_config = regression_config(SessionRole::Client, "bounded-rekey-reset", 1, None);
    let mut server_config = regression_config(SessionRole::Server, "bounded-rekey-reset", 1, None);
    client_config.deadlines.establish = Duration::from_secs(1);
    server_config.deadlines.establish = Duration::from_secs(1);
    client_config.deadlines.rekey_completion = Duration::from_secs(3);
    server_config.deadlines.rekey_completion = Duration::from_secs(3);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("bounded-rekey-reset", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let outgoing = outgoing.expect("open stream");
    let incoming = incoming.expect("accept stream");
    assert_eq!(server.internal_test_inbound_available_permits(), 0);
    let payload = Bytes::from(vec![0x5a; MAX_BUFFERED_STREAM_BYTES_V3 + 16 * 1024]);
    let mut offset = 0;
    while offset < payload.len() {
        offset += outgoing
            .write(payload.slice(offset..))
            .await
            .expect("write pre-reset data");
    }
    let rekeying = {
        let client = client.clone();
        tokio::spawn(async move { client.rekey().await })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if incoming.stream().internal_test_buffered_bytes() == MAX_BUFFERED_STREAM_BYTES_V3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rekey helper did not fill the bounded queue");
    tokio::time::timeout(Duration::from_millis(250), incoming.stream().reset())
        .await
        .expect("reset did not wake the capacity waiter")
        .expect("reset stream");
    assert_eq!(incoming.stream().internal_test_buffered_bytes(), 0);
    tokio::time::timeout(Duration::from_millis(250), rekeying)
        .await
        .expect("rekey task remained blocked after reset")
        .expect("join rekey task")
        .expect_err("reset must fail the pending rekey");
    assert_eq!(server.internal_test_inbound_available_permits(), 1);
    incoming
        .stream()
        .reset()
        .await
        .expect("repeated reset observes owned cleanup");
    assert_eq!(
        server.internal_test_inbound_available_permits(),
        1,
        "repeated reset released the stream permit more than once"
    );
    let _ = client.close().await;
    let _ = server.close().await;
}

#[tokio::test]
async fn local_reset_wakes_application_io_before_control_cleanup() {
    let (client_carrier, server_inner) = memory_carrier_pair_for_logical(1);
    let control_enabled = Arc::new(AtomicBool::new(false));
    let control_entered = Arc::new(Notify::new());
    let control_release = Arc::new(Notify::new());
    let control_gated: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: server_inner,
        enabled: control_enabled.clone(),
        writes: Arc::new(AtomicU64::new(0)),
        block_on: 1,
        entered: control_entered.clone(),
        release: control_release.clone(),
    });
    let write_enabled = Arc::new(AtomicBool::new(false));
    let write_entered = Arc::new(Notify::new());
    let write_release = Arc::new(Notify::new());
    let application_write_gated: Arc<dyn CarrierSessionV3> =
        Arc::new(BlockingNthWriteCarrierSession {
            inner: control_gated,
            enabled: write_enabled.clone(),
            writes: Arc::new(AtomicU64::new(0)),
            block_on: 1,
            entered: write_entered.clone(),
            release: write_release.clone(),
        });
    let read_enabled = Arc::new(AtomicBool::new(false));
    let read_entered = Arc::new(Notify::new());
    let read_release = Arc::new(Notify::new());
    let server_carrier: Arc<dyn CarrierSessionV3> =
        Arc::new(BlockingApplicationReadCarrierSession {
            inner: application_write_gated,
            accepts: AtomicU64::new(0),
            block_on: 2,
            enabled: read_enabled.clone(),
            entered: read_entered.clone(),
            release: read_release.clone(),
        });
    let client_config = regression_config(SessionRole::Client, "local-reset-io", 1, None);
    let server_config = regression_config(SessionRole::Server, "local-reset-io", 1, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("local-reset-io", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let outgoing = outgoing.expect("open stream");
    let incoming = Arc::new(incoming.expect("accept stream"));

    read_enabled.store(true, Ordering::Release);
    write_enabled.store(true, Ordering::Release);
    let reading_stream = incoming.clone();
    let reading = tokio::spawn(async move { reading_stream.stream().read().await });
    tokio::time::timeout(Duration::from_millis(250), read_entered.notified())
        .await
        .expect("application read never reached the carrier gate");
    let writing_stream = incoming.clone();
    let writing = tokio::spawn(async move {
        writing_stream
            .stream()
            .write(Bytes::from_static(b"blocked write"))
            .await
    });
    tokio::time::timeout(Duration::from_millis(250), write_entered.notified())
        .await
        .expect("application write never reached the carrier gate");

    write_enabled.store(false, Ordering::Release);
    control_enabled.store(true, Ordering::Release);
    let resetting_stream = incoming.clone();
    let mut resetting = tokio::spawn(async move { resetting_stream.stream().reset().await });
    tokio::time::timeout(Duration::from_millis(250), control_entered.notified())
        .await
        .expect("STREAM_RESET never reached the control write gate");

    let read_error = tokio::time::timeout(Duration::from_millis(250), reading)
        .await
        .expect("local reset did not wake the application read")
        .expect("join application read")
        .expect_err("local reset must fail the application read");
    assert_eq!(read_error, SessionError::StreamReset);
    let write_error = tokio::time::timeout(Duration::from_millis(250), writing)
        .await
        .expect("local reset did not wake the application write")
        .expect("join application write")
        .expect_err("local reset must fail the application write");
    assert_eq!(write_error, SessionError::StreamReset);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut resetting)
            .await
            .is_err(),
        "reset completed before the owned control cleanup was released"
    );

    control_release.notify_one();
    tokio::time::timeout(Duration::from_millis(250), resetting)
        .await
        .expect("reset did not finish after releasing control cleanup")
        .expect("join reset task")
        .expect("reset stream");
    read_release.notify_one();
    write_release.notify_one();
    drop(outgoing);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn encrypted_stream_reports_only_the_closed_terminal_error_set() {
    let (client, server) = establish_pair().await;
    let (opened, incoming) = tokio::join!(
        client.open_stream("typed-terminal", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let opened = opened.expect("open typed terminal stream");
    let incoming = incoming.expect("accept typed terminal stream");
    assert_eq!(opened.terminal_error(), None);
    assert_eq!(incoming.stream().terminal_error(), None);
    opened.reset().await.expect("reset stream");
    assert_eq!(
        opened.terminal_error(),
        Some(crate::SessionError::StreamReset)
    );
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn encrypted_stream_close_is_the_cleanup_alias_for_reset() {
    let (client, server) = establish_pair().await;
    let (opened, incoming) = tokio::join!(
        client.open_stream("close-reset", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let opened = opened.expect("open close stream");
    let incoming = incoming.expect("accept close stream");

    opened.close().await.expect("close stream");
    assert_eq!(
        opened.terminal_error(),
        Some(crate::SessionError::StreamReset)
    );
    assert_eq!(
        incoming.stream().read().await.expect_err("peer reset"),
        crate::SessionError::StreamReset
    );

    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn reset_after_peer_fin_confirms_control_before_physical_reset() {
    let (client_carrier, server_inner) = memory_carrier_pair_for_logical(2);
    let close_writes = Arc::new(AtomicU64::new(0));
    let resets = Arc::new(AtomicU64::new(0));
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(ResetAfterFinCarrierSession {
        inner: server_inner,
        accepts: AtomicU64::new(0),
        close_writes: close_writes.clone(),
        resets: resets.clone(),
        reset_entered: None,
        reset_release: None,
    });
    let client_config = regression_config(SessionRole::Client, "reset-after-peer-fin", 2, None);
    let server_config = regression_config(SessionRole::Server, "reset-after-peer-fin", 2, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("reset-after-peer-fin", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let outgoing = outgoing.expect("open stream");
    let incoming = incoming.expect("accept stream");

    outgoing.close_write().await.expect("send peer FIN");
    assert_eq!(incoming.stream().read().await.expect("read peer FIN"), None);
    incoming
        .stream()
        .reset()
        .await
        .expect("reset after peer FIN");
    assert_eq!(close_writes.load(Ordering::Acquire), 0);
    assert_eq!(resets.load(Ordering::Acquire), 1);
    assert_eq!(outgoing.read().await, Err(SessionError::StreamReset));

    let (sibling, sibling_incoming) = tokio::join!(
        client.open_stream("reset-sibling", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let sibling = sibling.expect("open sibling");
    let sibling_incoming = sibling_incoming.expect("accept sibling");
    sibling
        .write(Bytes::from_static(b"alive"))
        .await
        .expect("write sibling");
    assert_eq!(
        sibling_incoming
            .stream()
            .read()
            .await
            .expect("read sibling"),
        Some(Bytes::from_static(b"alive"))
    );
    sibling.reset().await.expect("reset sibling");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn reset_control_write_failure_terminates_session_and_finishes_physical_cleanup() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let fail_next_control_write = Arc::new(AtomicBool::new(false));
    let application_reset_entered = Arc::new(AtomicU64::new(0));
    let application_resets = Arc::new(AtomicU64::new(0));
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(FailingControlWriteCarrierSession {
        inner: client_inner,
        opens: AtomicU64::new(0),
        fail_next_control_write: fail_next_control_write.clone(),
        application_reset_entered: application_reset_entered.clone(),
        application_resets: application_resets.clone(),
    });
    let client_config = regression_config(SessionRole::Client, "reset-control-failure", 1, None);
    let server_config = regression_config(SessionRole::Server, "reset-control-failure", 1, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("reset-control-failure", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let outgoing = outgoing.expect("open stream");
    let incoming = incoming.expect("accept stream");

    fail_next_control_write.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_millis(250), outgoing.reset())
        .await
        .expect("reset cleanup waiter remained blocked")
        .expect("physical reset cleanup must still complete");
    assert_eq!(
        application_reset_entered.load(Ordering::Acquire),
        1,
        "control failure must start physical reset exactly once"
    );
    assert_eq!(
        application_resets.load(Ordering::Acquire),
        1,
        "control failure must finish physical reset exactly once"
    );

    let termination = tokio::time::timeout(Duration::from_millis(250), client.wait_termination())
        .await
        .expect("control write failure did not terminate the session");
    assert_eq!(termination.error, SessionError::Closed);
    assert!(
        client
            .open_stream("after-control-failure", StreamMetadata::empty())
            .await
            .is_err(),
        "session remained reusable after consuming an unsent control sequence"
    );
    drop(incoming);
    let _ = server.close().await;
}

#[tokio::test]
async fn canceled_reset_waiter_does_not_cancel_owned_cleanup() {
    let (client_carrier, server_inner) = memory_carrier_pair_for_logical(1);
    let reset_entered = Arc::new(Notify::new());
    let reset_release = Arc::new(Semaphore::new(0));
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(ResetAfterFinCarrierSession {
        inner: server_inner,
        accepts: AtomicU64::new(0),
        close_writes: Arc::new(AtomicU64::new(0)),
        resets: Arc::new(AtomicU64::new(0)),
        reset_entered: Some(reset_entered.clone()),
        reset_release: Some(reset_release.clone()),
    });
    let client_config = regression_config(SessionRole::Client, "owned-reset-cleanup", 1, None);
    let server_config = regression_config(SessionRole::Server, "owned-reset-cleanup", 1, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("owned-reset-cleanup", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let outgoing = outgoing.expect("open stream");
    let incoming = incoming.expect("accept stream");

    let mut resetting = Box::pin(incoming.stream().reset());
    tokio::select! {
        result = &mut resetting => panic!("reset completed before carrier cleanup gate: {result:?}"),
        _ = reset_entered.notified() => {}
    }
    drop(resetting);
    let mut next_opening = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("permit-after-canceled-reset", StreamMetadata::empty())
                .await
        })
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut next_opening)
            .await
            .is_err(),
        "logical permit released before physical reset completed"
    );
    reset_release.add_permits(1);
    tokio::time::timeout(Duration::from_millis(250), incoming.stream().reset())
        .await
        .expect("owned cleanup stopped with its first waiter")
        .expect("repeat reset observes cleanup success");
    assert_eq!(outgoing.read().await, Err(SessionError::StreamReset));

    let (next, next_incoming) = tokio::join!(next_opening, server.accept_stream());
    let next = next
        .expect("join replacement open")
        .expect("reset released stream permit");
    let next_incoming = next_incoming.expect("accept stream after reset");
    next.write(Bytes::from_static(b"next"))
        .await
        .expect("write next stream");
    assert_eq!(
        next_incoming
            .stream()
            .read()
            .await
            .expect("read next stream"),
        Some(Bytes::from_static(b"next"))
    );
    next.reset().await.expect("reset next stream");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn simultaneous_peer_reset_does_not_release_capacity_before_owned_cleanup() {
    let (client_carrier, server_inner) = memory_carrier_pair_for_logical(1);
    let resets = Arc::new(AtomicU64::new(0));
    let reset_entered = Arc::new(Notify::new());
    let reset_release = Arc::new(Semaphore::new(0));
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(ResetAfterFinCarrierSession {
        inner: server_inner,
        accepts: AtomicU64::new(0),
        close_writes: Arc::new(AtomicU64::new(0)),
        resets: resets.clone(),
        reset_entered: Some(reset_entered.clone()),
        reset_release: Some(reset_release.clone()),
    });
    let client_config = regression_config(SessionRole::Client, "simultaneous-reset", 1, None);
    let server_config = regression_config(SessionRole::Server, "simultaneous-reset", 1, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("simultaneous-reset", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let outgoing = outgoing.expect("open stream");
    let incoming = incoming.expect("accept stream");

    let mut local_reset = Box::pin(incoming.stream().reset());
    tokio::select! {
        result = &mut local_reset => panic!("local reset completed before carrier gate: {result:?}"),
        _ = reset_entered.notified() => {}
    }
    outgoing
        .reset()
        .await
        .expect("send simultaneous peer reset");

    let mut repeated_reset = Box::pin(incoming.stream().reset());
    let mut next_opening = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("permit-after-simultaneous-reset", StreamMetadata::empty())
                .await
        })
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut repeated_reset)
            .await
            .is_err(),
        "repeat reset completed before the owned physical cleanup"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut next_opening)
            .await
            .is_err(),
        "logical capacity released before the owned physical cleanup"
    );
    assert_eq!(
        resets.load(Ordering::Acquire),
        1,
        "peer reset must not start a second physical reset"
    );

    reset_release.add_permits(1);
    tokio::time::timeout(Duration::from_millis(250), &mut local_reset)
        .await
        .expect("owned physical cleanup remained blocked")
        .expect("owned physical cleanup succeeded");
    tokio::time::timeout(Duration::from_millis(250), &mut repeated_reset)
        .await
        .expect("repeat reset did not observe shared completion")
        .expect("repeat reset observed cleanup success");
    tokio::time::timeout(Duration::from_millis(250), client.probe_liveness())
        .await
        .expect("control probe remained blocked after cleanup")
        .expect("control probe after peer reset");
    assert_eq!(
        resets.load(Ordering::Acquire),
        1,
        "processed peer reset must share the owned physical cleanup"
    );
    let (next, next_incoming) = tokio::join!(next_opening, server.accept_stream());
    let next = next
        .expect("join replacement open")
        .expect("cleanup released logical capacity");
    let next_incoming = next_incoming.expect("accept replacement stream");
    next.reset().await.expect("reset replacement stream");
    drop(next_incoming);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn simultaneous_rekey_keeps_the_ordered_control_stream_live() {
    let (client, server) = establish_pair().await;
    let (stream, incoming) = tokio::join!(
        client.open_stream("simultaneous", StreamMetadata::empty()),
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
    let (client_carrier, server_carrier) = memory_carrier_pair_v3();
    let client = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "max-stream-binding".into(),
        session_contract_hash: [5; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
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
    let server = SessionConfigV3 {
        role: SessionRole::Server,
        max_inbound_streams: 5,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client),
        establish_session_v3(server_carrier, server),
    );
    assert!(client.is_err() || server.is_err());
}

#[tokio::test]
async fn injected_establish_deadline_bounds_a_blackholed_peer() {
    let (client_carrier, _blackhole_peer) = memory_carrier_pair_v3();
    let error = establish_session_v3(
        client_carrier,
        SessionConfigV3 {
            role: SessionRole::Client,
            path: PathKind::Direct,
            channel_id: "establish-deadline".into(),
            session_contract_hash: [1; 32],
            suite: CipherSuiteV3::ChaCha20Poly1305,
            psk: deterministic_test_bytes(2),
            max_inbound_streams: 4,
            idle_timeout: Duration::ZERO,
            local_admission_binding: [3; 32],
            peer_admission_binding: Some([4; 32]),
            local_endpoint_instance_id: None,
            expected_peer_endpoint_instance_id: None,
            rpc_handler: None,
            deadlines: SessionDeadlinesV3 {
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
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: Arc::new(AtomicBool::new(false)),
        write_entered: Arc::new(Notify::new()),
        release_write: Arc::new(Notify::new()),
    });
    let client_carrier: Arc<dyn CarrierSessionV3> =
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
        establish_session_v3(client_carrier, client),
        establish_session_v3(server_carrier, server),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");

    enabled.store(true, Ordering::Release);
    let opening = {
        let server = server.clone();
        tokio::spawn(async move {
            server
                .open_stream("prepare-timeout", StreamMetadata::empty())
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
    assert_eq!(error, SessionError::RekeyFailed);
    release.notify_one();
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
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
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
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
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
        2,
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
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedCarrierSession {
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
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
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
    release.notify_one();

    tokio::time::timeout(Duration::from_millis(750), client.rekey())
        .await
        .expect("owned completion did not release the rekey slot")
        .expect("later rekey after dropped committed future");
    client.probe_liveness().await.expect("session remains live");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn close_is_bounded_when_a_dropped_committed_rekey_holds_its_lock() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let gate = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: gate.clone(),
        write_entered: entered.clone(),
        release_write: release.clone(),
    });
    let mut client_config = regression_config(SessionRole::Client, "close-owned-rekey", 1, None);
    let mut server_config = regression_config(SessionRole::Server, "close-owned-rekey", 1, None);
    client_config.deadlines.rekey_prepare = Duration::from_millis(500);
    server_config.deadlines.rekey_prepare = Duration::from_millis(500);
    client_config.deadlines.rekey_completion = Duration::from_millis(500);
    server_config.deadlines.rekey_completion = Duration::from_millis(500);
    client_config.deadlines.close_flush = Duration::from_millis(25);
    server_config.deadlines.close_flush = Duration::from_millis(25);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
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
        .expect("rekey never reached its committed control write");
    rekeying.abort();
    rekeying
        .await
        .expect_err("caller future must be canceled after commit");

    let closing = {
        let client = client.clone();
        tokio::spawn(async move { client.close().await })
    };
    let close_result = tokio::time::timeout(Duration::from_millis(200), closing)
        .await
        .expect("Close escaped its close_flush deadline")
        .expect("join Close");
    assert_eq!(close_result, Err(SessionError::Timeout));
    release.notify_waiters();
    assert_eq!(client.rekey().await, Err(SessionError::Closed));

    let _ = server.close().await;
}

#[tokio::test]
async fn committed_rekey_completion_timeout_projects_rekey_failed_and_timeout() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let gate = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: gate.clone(),
        write_entered: entered.clone(),
        release_write: release.clone(),
    });
    let mut client_config = regression_config(SessionRole::Client, "rekey-owned-timeout", 1, None);
    let server_config = regression_config(SessionRole::Server, "rekey-owned-timeout", 1, None);
    client_config.deadlines.rekey_prepare = Duration::from_millis(500);
    client_config.deadlines.rekey_completion = Duration::from_millis(25);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
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
        .expect("rekey never reached its committed control write");
    assert_eq!(
        rekeying.await.expect("join rekey task"),
        Err(SessionError::RekeyFailed)
    );
    let termination = tokio::time::timeout(Duration::from_millis(500), client.wait_termination())
        .await
        .expect("owned rekey completion timeout did not terminate the session");
    assert_eq!(termination.error, SessionError::Timeout);

    gate.store(false, Ordering::Release);
    release.notify_one();
    let _ = tokio::join!(client.close(), server.close());
}

#[tokio::test]
async fn committed_rekey_control_write_failure_projects_rekey_failed_and_operation_failed() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let fail_next_control_write = Arc::new(AtomicBool::new(false));
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(FailingControlWriteCarrierSession {
        inner: client_inner,
        opens: AtomicU64::new(0),
        fail_next_control_write: fail_next_control_write.clone(),
        application_reset_entered: Arc::new(AtomicU64::new(0)),
        application_resets: Arc::new(AtomicU64::new(0)),
    });
    let client_config = regression_config(SessionRole::Client, "rekey-write-failure", 1, None);
    let server_config = regression_config(SessionRole::Server, "rekey-write-failure", 1, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");

    fail_next_control_write.store(true, Ordering::Release);
    assert_eq!(client.rekey().await, Err(SessionError::RekeyFailed));
    let termination = tokio::time::timeout(Duration::from_millis(500), client.wait_termination())
        .await
        .expect("post-commit write failure did not terminate the session");
    assert_eq!(termination.error, SessionError::OperationFailed);

    let _ = tokio::join!(client.close(), server.close());
}

#[tokio::test]
async fn dropped_committed_rekey_still_times_out_under_session_ownership() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let gate = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: gate.clone(),
        write_entered: entered.clone(),
        release_write: release.clone(),
    });
    let mut client_config =
        regression_config(SessionRole::Client, "dropped-rekey-timeout", 1, None);
    let server_config = regression_config(SessionRole::Server, "dropped-rekey-timeout", 1, None);
    client_config.deadlines.rekey_prepare = Duration::from_millis(500);
    client_config.deadlines.rekey_completion = Duration::from_millis(100);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
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
        .expect("rekey never reached its committed control write");
    rekeying.abort();
    rekeying
        .await
        .expect_err("caller future must be canceled after commit");
    let termination = tokio::time::timeout(Duration::from_millis(500), client.wait_termination())
        .await
        .expect("session-owned completion timeout did not terminate the session");
    assert_eq!(termination.error, SessionError::Timeout);

    gate.store(false, Ordering::Release);
    release.notify_one();
    let _ = tokio::join!(client.close(), server.close());
}

#[tokio::test]
async fn failed_outbound_carrier_open_commits_abandonment_before_later_rekey() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(2);
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(FailingNthOpenCarrierSession {
        inner: client_inner,
        opens: AtomicU64::new(0),
        fail_on: 2,
    });
    let client_config = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "open-abandonment".into(),
        session_contract_hash: [0x71; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [0x72; 32],
        max_inbound_streams: 2,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV3 {
            rekey_prepare: Duration::from_millis(200),
            rekey_completion: Duration::from_millis(200),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
    assert!(
        client
            .open_stream("fails-before-fss3", StreamMetadata::empty())
            .await
            .is_err()
    );
    let (stream, incoming) = tokio::join!(
        client.open_stream("after-abandonment", StreamMetadata::empty()),
        server.accept_stream(),
    );
    assert_eq!(stream.expect("later stream").internal_test_id(), 3);
    assert_eq!(incoming.expect("later incoming").internal_test_id(), 3);
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
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: gate.clone(),
        write_entered: write_entered.clone(),
        release_write: release_write.clone(),
    });
    let client_config = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "cancel-open-setup".into(),
        session_contract_hash: [0x77; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [0x78; 32],
        max_inbound_streams: 2,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV3 {
            rekey_prepare: Duration::from_millis(300),
            rekey_completion: Duration::from_millis(300),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
    gate.store(true, Ordering::Release);
    let opening = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("cancel-during-fss3", StreamMetadata::empty())
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), write_entered.notified())
        .await
        .expect("open never reached blocked FSS3 write");
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
        client.open_stream("after-cancel", StreamMetadata::empty()),
        server.accept_stream(),
    );
    assert_eq!(stream.expect("later stream").internal_test_id(), 3);
    assert_eq!(incoming.expect("later incoming").internal_test_id(), 3);
    tokio::time::timeout(Duration::from_millis(700), client.rekey())
        .await
        .expect("rekey remained stuck behind canceled open")
        .expect("rekey after canceled open");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn canceled_abandonment_finishes_the_in_flight_reset_record() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicU64::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let blocked: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: client_inner,
        enabled: enabled.clone(),
        writes: writes.clone(),
        block_on: 1,
        entered: entered.clone(),
        release: release.clone(),
    });
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(FailingNthOpenCarrierSession {
        inner: blocked,
        opens: AtomicU64::new(0),
        fail_on: 2,
    });
    let client_config = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "cancel-partial-reset".into(),
        session_contract_hash: [0x7b; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
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
    let server_config = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    writes.store(0, Ordering::Release);
    enabled.store(true, Ordering::Release);
    let opening = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("fails-before-fss3", StreamMetadata::empty())
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("STREAM_RESET record write never blocked");
    opening.abort();
    release.notify_one();

    enabled.store(false, Ordering::Release);
    let (stream, incoming) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(
            client.open_stream("after-in-flight-reset", StreamMetadata::empty()),
            server.accept_stream(),
        )
    })
    .await
    .expect("later open remained blocked behind canceled abandonment");
    assert_eq!(stream.expect("later stream").internal_test_id(), 3);
    assert_eq!(incoming.expect("later incoming").internal_test_id(), 3);
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
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: client_gate.clone(),
        write_entered: client_entered.clone(),
        release_write: client_release.clone(),
    });
    let server_enabled = Arc::new(AtomicBool::new(false));
    let server_writes = Arc::new(AtomicU64::new(0));
    let server_entered = Arc::new(Notify::new());
    let server_release = Arc::new(Notify::new());
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: server_inner,
        enabled: server_enabled.clone(),
        writes: server_writes.clone(),
        block_on: 2,
        entered: server_entered.clone(),
        release: server_release.clone(),
    });
    let client_config = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "goaway-tightens-open".into(),
        session_contract_hash: [0x79; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [0x7a; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV3 {
            close_flush: Duration::from_millis(500),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    client_gate.store(true, Ordering::Release);
    let opening = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("past-boundary", StreamMetadata::empty())
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), client_entered.notified())
        .await
        .expect("open never reached blocked FSS3 write");

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
    client_release.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(1), opening)
        .await
        .expect("open did not observe tightened GOAWAY boundary")
        .expect("join open task")
        .expect_err("open past GOAWAY boundary must fail");
    assert_eq!(error, SessionError::GoingAway);
    server_release.notify_one();
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
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(GatedCarrierSession {
        inner: client_inner,
        gate: gate.clone(),
        write_entered: Arc::new(Notify::new()),
        release_write: Arc::new(Notify::new()),
    });
    let client_config = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "bounded-close-flush".into(),
        session_contract_hash: [0x73; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [0x74; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::ZERO,
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV3 {
            close_flush: Duration::from_millis(20),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
    gate.store(true, Ordering::Release);
    let error = tokio::time::timeout(Duration::from_millis(250), client.close())
        .await
        .expect("close ignored its flush deadline")
        .expect_err("stalled close flush must report timeout");
    assert_eq!(error, SessionError::Timeout);
    gate.store(false, Ordering::Release);
    let _ = server.close().await;
}

#[tokio::test]
async fn receive_rekey_commits_before_the_ack_is_exposed_to_unreliable_delivery() {
    let (client_inner, server_inner) = memory_carrier_pair_for_logical(1);
    let (client_to_server_tx, client_to_server_rx) = mpsc::unbounded_channel();
    let (server_to_client_tx, server_to_client_rx) = mpsc::unbounded_channel();
    let server_gate = Arc::new(PostWriteGate {
        enabled: AtomicBool::new(false),
        writes: AtomicU64::new(0),
        block_on: 1,
        entered: Notify::new(),
        release: Semaphore::new(0),
    });
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(TestDatagramCarrierSession {
        inner: client_inner,
        outgoing: client_to_server_tx,
        incoming: TokioMutex::new(server_to_client_rx),
        streams: AtomicU64::new(0),
        control_post_write_gate: None,
    });
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(TestDatagramCarrierSession {
        inner: server_inner,
        outgoing: server_to_client_tx,
        incoming: TokioMutex::new(client_to_server_rx),
        streams: AtomicU64::new(0),
        control_post_write_gate: Some(server_gate.clone()),
    });
    let mut client_config =
        regression_config(SessionRole::Client, "rekey-ack-publication", 1, None);
    client_config.deadlines.rekey_completion = Duration::from_millis(500);
    let mut server_config =
        regression_config(SessionRole::Server, "rekey-ack-publication", 1, None);
    server_config.deadlines.rekey_completion = Duration::from_millis(500);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
    server_gate.enabled.store(true, Ordering::Release);

    let rekeying = tokio::spawn({
        let client = client.clone();
        async move { client.rekey().await }
    });
    tokio::time::timeout(Duration::from_secs(1), server_gate.entered.notified())
        .await
        .expect("server rekey ACK was not exposed before its write returned");
    tokio::time::timeout(Duration::from_secs(1), rekeying)
        .await
        .expect("client did not receive the exposed rekey ACK")
        .expect("join client rekey")
        .expect("client rekey");

    client
        .unreliable_messages()
        .expect("negotiated unreliable channel")
        .send(
            Bytes::from_static(b"epoch-one"),
            SystemTime::now() + Duration::from_secs(30),
        )
        .await
        .expect("send epoch-one unreliable message");
    let received = tokio::time::timeout(
        Duration::from_millis(250),
        server
            .unreliable_messages()
            .expect("negotiated unreliable channel")
            .receive(),
    )
    .await
    .expect("receiver dropped a valid post-ACK epoch-one message")
    .expect("receive epoch-one unreliable message");
    assert_eq!(received, Bytes::from_static(b"epoch-one"));

    server_gate.release.add_permits(1);
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn previous_version_datagram_fails_the_established_session() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v3/version_isolation_vectors.json"
    ))
    .unwrap();
    let vector = fixture["frames"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == "fsd3")
        .unwrap();
    for field in ["v2_magic_hex", "v2_version_hex"] {
        let encoded = vector[field].as_str().unwrap();
        let wire = encoded
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let (client_inner, server_inner) = memory_carrier_pair_for_logical(1);
        let (client_to_server_tx, client_to_server_rx) = mpsc::unbounded_channel();
        let (server_to_client_tx, server_to_client_rx) = mpsc::unbounded_channel();
        let inject_client = server_to_client_tx.clone();
        let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(TestDatagramCarrierSession {
            inner: client_inner,
            outgoing: client_to_server_tx,
            incoming: TokioMutex::new(server_to_client_rx),
            streams: AtomicU64::new(0),
            control_post_write_gate: None,
        });
        let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(TestDatagramCarrierSession {
            inner: server_inner,
            outgoing: server_to_client_tx,
            incoming: TokioMutex::new(client_to_server_rx),
            streams: AtomicU64::new(0),
            control_post_write_gate: None,
        });
        let client_config = regression_config(SessionRole::Client, field, 1, None);
        let server_config = regression_config(SessionRole::Server, field, 1, None);
        let (client, server) = tokio::join!(
            establish_session_v3(client_carrier, client_config),
            establish_session_v3(server_carrier, server_config),
        );
        let client = client.expect("client Session");
        let server = server.expect("server Session");
        inject_client.send(Bytes::from(wire)).unwrap();
        assert_eq!(
            client.unreliable_messages().unwrap().receive().await,
            Err(UnreliableMessageError::Closed),
            "{field}"
        );
        assert_eq!(
            client.wait_termination().await.error,
            SessionError::OperationFailed,
            "{field}"
        );
        let _ = server.close().await;
    }
}

#[tokio::test]
async fn close_omits_a_duplicate_goaway_after_a_prior_goaway() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicU64::new(0));
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: client_inner,
        enabled: enabled.clone(),
        writes: writes.clone(),
        block_on: u64::MAX,
        entered: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let client_config = regression_config(SessionRole::Client, "idempotent-goaway", 1, None);
    let server_config = regression_config(SessionRole::Server, "idempotent-goaway", 1, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
    writes.store(0, Ordering::Release);
    enabled.store(true, Ordering::Release);

    client
        .internal_test_send_goaway(5)
        .await
        .expect("send prior GOAWAY");
    assert_eq!(writes.load(Ordering::Acquire), 1);
    client.close().await.expect("close after prior GOAWAY");
    assert_eq!(
        writes.load(Ordering::Acquire),
        2,
        "close must add only SESSION_CLOSE after a prior GOAWAY"
    );
    server.close().await.expect("close server");
}

#[tokio::test]
async fn close_finishes_control_stream_before_carrier_shutdown() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let next_order = Arc::new(AtomicU64::new(0));
    let control_finish_order = Arc::new(AtomicU64::new(0));
    let carrier_close_order = Arc::new(AtomicU64::new(0));
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(ControlFlushOrderCarrierSession {
        inner: client_inner,
        next_order,
        control_finish_order: control_finish_order.clone(),
        carrier_close_order: carrier_close_order.clone(),
    });
    let client_config = regression_config(SessionRole::Client, "ordered-control-flush", 1, None);
    let server_config = regression_config(SessionRole::Server, "ordered-control-flush", 1, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    client.close().await.expect("close client");
    let finish_order = control_finish_order.load(Ordering::Acquire);
    let close_order = carrier_close_order.load(Ordering::Acquire);
    assert_ne!(finish_order, 0, "close must finish the control stream");
    assert!(
        finish_order < close_order,
        "control FIN order {finish_order} must precede carrier close order {close_order}"
    );
    let _ = server.close().await;
}

#[tokio::test]
async fn close_accepts_terminal_records_from_the_pre_ack_control_epoch() {
    let (client_inner, server_inner) = memory_carrier_pair_for_logical(1);
    let client_enabled = Arc::new(AtomicBool::new(false));
    let client_writes = Arc::new(AtomicU64::new(0));
    let client_entered = Arc::new(Notify::new());
    let client_release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: client_inner,
        enabled: client_enabled.clone(),
        writes: client_writes.clone(),
        block_on: 1,
        entered: client_entered.clone(),
        release: client_release.clone(),
    });
    let server_enabled = Arc::new(AtomicBool::new(false));
    let server_writes = Arc::new(AtomicU64::new(0));
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: server_inner,
        enabled: server_enabled.clone(),
        writes: server_writes.clone(),
        block_on: u64::MAX,
        entered: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let mut client_config =
        regression_config(SessionRole::Client, "pre-ack-terminal-epoch", 1, None);
    client_config.deadlines.close_flush = Duration::from_millis(500);
    client_config.deadlines.rekey_completion = Duration::from_millis(500);
    let mut server_config =
        regression_config(SessionRole::Server, "pre-ack-terminal-epoch", 1, None);
    server_config.deadlines.close_flush = Duration::from_millis(500);
    server_config.deadlines.rekey_completion = Duration::from_millis(500);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
    client_writes.store(0, Ordering::Release);
    server_writes.store(0, Ordering::Release);
    client_enabled.store(true, Ordering::Release);
    server_enabled.store(true, Ordering::Release);

    let server_rekey = tokio::spawn({
        let server = server.clone();
        async move { server.rekey().await }
    });
    tokio::time::timeout(Duration::from_secs(1), client_entered.notified())
        .await
        .expect("client did not block its rekey ACK");
    let server_close = tokio::spawn({
        let server = server.clone();
        async move { server.close().await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while server_writes.load(Ordering::Acquire) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server did not write its pre-ACK terminal sequence");
    client_release.notify_one();

    let (server_rekey, server_close) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(server_rekey, server_close)
    })
    .await
    .expect("rekey and close did not converge");
    let _ = server_rekey.expect("join server rekey");
    server_close
        .expect("join server close")
        .expect("close server");
    client.close().await.expect("close client");
    assert_eq!(client_writes.load(Ordering::Acquire), 2);
    assert_eq!(server_writes.load(Ordering::Acquire), 3);
}

#[tokio::test]
async fn close_terminal_sequence_suppresses_a_queued_pong() {
    let (client_inner, server_inner) = memory_carrier_pair_for_logical(1);
    let client_enabled = Arc::new(AtomicBool::new(false));
    let client_writes = Arc::new(AtomicU64::new(0));
    let client_entered = Arc::new(Notify::new());
    let client_release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: client_inner,
        enabled: client_enabled.clone(),
        writes: client_writes.clone(),
        block_on: 1,
        entered: client_entered.clone(),
        release: client_release.clone(),
    });
    let server_enabled = Arc::new(AtomicBool::new(false));
    let server_writes = Arc::new(AtomicU64::new(0));
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: server_inner,
        enabled: server_enabled.clone(),
        writes: server_writes.clone(),
        block_on: u64::MAX,
        entered: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    });
    let mut client_config =
        regression_config(SessionRole::Client, "terminal-control-sequence", 1, None);
    client_config.deadlines.close_flush = Duration::from_millis(500);
    let mut server_config =
        regression_config(SessionRole::Server, "terminal-control-sequence", 1, None);
    server_config.deadlines.close_flush = Duration::from_millis(500);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
    client_writes.store(0, Ordering::Release);
    server_writes.store(0, Ordering::Release);
    client_enabled.store(true, Ordering::Release);
    server_enabled.store(true, Ordering::Release);

    let client_close = tokio::spawn({
        let client = client.clone();
        async move { client.close().await }
    });
    tokio::time::timeout(Duration::from_secs(1), client_entered.notified())
        .await
        .expect("client close did not block its GOAWAY write");
    let server_probe = tokio::spawn({
        let server = server.clone();
        async move { server.probe_liveness().await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while server_writes.load(Ordering::Acquire) < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server did not send its PING");
    let server_close = tokio::spawn(async move { server.close().await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while server_writes.load(Ordering::Acquire) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server did not send its terminal control sequence");
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    client_release.notify_one();

    let (client_close, server_close, server_probe) =
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(client_close, server_close, server_probe)
        })
        .await
        .expect("concurrent terminal control sequences did not converge");
    client_close
        .expect("join client close")
        .expect("close client");
    server_close
        .expect("join server close")
        .expect("close server");
    assert!(
        server_probe.expect("join server probe").is_err(),
        "in-flight probe must terminate with its closing Session"
    );
    assert_eq!(
        client_writes.load(Ordering::Acquire),
        2,
        "PONG must not interleave with GOAWAY, SESSION_CLOSE, and control FIN"
    );
}

#[tokio::test]
async fn signed_idle_timeout_is_refreshed_by_protocol_activity() {
    let (client_carrier, server_carrier) = memory_carrier_pair_for_logical(1);
    let client_config = SessionConfigV3 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "signed-idle-timeout".into(),
        session_contract_hash: [0x75; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: [0x76; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::from_millis(80),
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: None,
        deadlines: SessionDeadlinesV3 {
            close_flush: Duration::from_millis(20),
            ..Default::default()
        },
    };
    let server_config = SessionConfigV3 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
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
    let terminal = tokio::time::timeout(Duration::from_millis(500), client.wait_termination())
        .await
        .expect("idle watchdog did not terminate the session");
    assert_eq!(terminal.error, SessionError::Timeout);
    assert!(client.probe_liveness().await.is_err());
    assert!(server.probe_liveness().await.is_err());
}

#[derive(Debug)]
struct TerminationObservingCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
    terminations: Arc<AtomicU64>,
}

#[derive(Debug)]
struct HangingCloseCarrierSession {
    inner: Arc<dyn CarrierSessionV3>,
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
impl CarrierSessionV3 for HangingCloseCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.accept_stream().await
    }

    async fn close(&self) -> io::Result<()> {
        self.active_closes.fetch_add(1, Ordering::AcqRel);
        let _guard = ActiveCloseGuard(self.active_closes.clone());
        std::future::pending().await
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

#[async_trait::async_trait]
impl CarrierSessionV3 for TerminationObservingCarrierSession {
    fn kind(&self) -> CarrierKind {
        self.inner.kind()
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.open_stream().await
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner.accept_stream().await
    }

    async fn close(&self) -> io::Result<()> {
        self.terminations.fetch_add(1, Ordering::AcqRel);
        self.inner.close().await
    }

    fn abort(&self) {
        self.terminations.fetch_add(1, Ordering::AcqRel);
        self.inner.abort();
    }
}

fn regression_config(
    role: SessionRole,
    channel_id: &str,
    max_inbound_streams: u16,
    rpc_handler: Option<Arc<dyn RpcHandlerV3>>,
) -> SessionConfigV3 {
    let (local_admission_binding, peer_admission_binding) = match role {
        SessionRole::Client => ([1; 32], Some([2; 32])),
        SessionRole::Server => ([2; 32], Some([1; 32])),
    };
    SessionConfigV3 {
        role,
        path: PathKind::Direct,
        channel_id: channel_id.into(),
        session_contract_hash: [0x81; 32],
        suite: CipherSuiteV3::ChaCha20Poly1305,
        psk: deterministic_test_bytes(0x82),
        max_inbound_streams,
        idle_timeout: Duration::ZERO,
        local_admission_binding,
        peer_admission_binding,
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler,
        deadlines: SessionDeadlinesV3 {
            establish: Duration::from_secs(1),
            rekey_prepare: Duration::from_millis(100),
            rekey_completion: Duration::from_millis(100),
            close_flush: Duration::from_millis(20),
        },
    }
}

#[tokio::test]
async fn direct_and_tunnel_endpoint_identity_shapes_fail_before_carrier_io() {
    let (direct_carrier, _direct_peer) = memory_carrier_pair_v3();
    let mut direct = regression_config(SessionRole::Client, "invalid-direct-endpoint", 1, None);
    direct.local_endpoint_instance_id = Some("must-not-exist".into());
    direct.expected_peer_endpoint_instance_id = Some("must-not-exist".into());
    let direct_error = establish_session_v3(direct_carrier, direct)
        .await
        .expect_err("direct endpoint identities must be absent");
    assert_eq!(direct_error.kind(), io::ErrorKind::InvalidData);

    let (tunnel_carrier, _tunnel_peer) = memory_carrier_pair_v3();
    let mut tunnel = regression_config(SessionRole::Client, "invalid-tunnel-endpoint", 1, None);
    tunnel.path = PathKind::Tunnel;
    tunnel.local_endpoint_instance_id = Some("endpoint-client".into());
    let tunnel_error = establish_session_v3(tunnel_carrier, tunnel)
        .await
        .expect_err("tunnel endpoint identities must both be present");
    assert_eq!(tunnel_error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn protocol_failure_closes_carrier_and_wakes_blocked_accept() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let injected_client_carrier = client_inner.clone();
    let terminations = Arc::new(AtomicU64::new(0));
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(TerminationObservingCarrierSession {
        inner: client_inner,
        terminations: terminations.clone(),
    });
    let (client, server) = tokio::join!(
        establish_session_v3(
            client_carrier,
            regression_config(SessionRole::Client, "failure-cleanup", 1, None),
        ),
        establish_session_v3(
            server_carrier.clone(),
            regression_config(SessionRole::Server, "failure-cleanup", 1, None),
        ),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
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
    assert_eq!(error, SessionError::Closed);
    tokio::time::timeout(Duration::from_millis(250), async {
        while terminations.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("protocol failure did not terminate the local carrier");
    let first_cause = client.wait_termination().await.error;
    let repeated_cause = client.wait_termination().await.error;
    assert_eq!(first_cause, SessionError::Closed);
    assert_eq!(repeated_cause, first_cause);
    assert_eq!(repeated_cause.to_string(), first_cause.to_string());
    let _ = server.close().await;
}

#[tokio::test]
async fn stalled_fss3_does_not_block_later_authenticated_streams() {
    let (client_carrier, server_carrier) = memory_carrier_pair_for_logical(2);
    let raw_client_carrier = client_carrier.clone();
    let (client, server) = tokio::join!(
        establish_session_v3(
            client_carrier,
            regression_config(SessionRole::Client, "stalled-fss3", 2, None),
        ),
        establish_session_v3(
            server_carrier,
            regression_config(SessionRole::Server, "stalled-fss3", 2, None),
        ),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    let stalled = raw_client_carrier
        .open_stream()
        .await
        .expect("open carrier stream without FSS3");
    tokio::time::sleep(Duration::from_millis(10)).await;
    let (outgoing, incoming) = tokio::time::timeout(Duration::from_millis(250), async {
        tokio::join!(
            client.open_stream("after-stalled-fss3", StreamMetadata::empty()),
            server.accept_stream(),
        )
    })
    .await
    .expect("stalled FSS3 caused session-level head-of-line blocking");
    assert_eq!(
        outgoing
            .expect("authenticated outgoing stream")
            .internal_test_id(),
        1
    );
    assert_eq!(
        incoming
            .expect("authenticated incoming stream")
            .internal_test_id(),
        1
    );
    stalled.reset().await.expect("reset stalled carrier stream");
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn queued_data_open_does_not_starve_reserved_rpc_capacity() {
    let (client_carrier, server_carrier) = memory_carrier_pair_for_logical(1);
    let (client, server) = tokio::join!(
        establish_session_v3(
            client_carrier,
            regression_config(SessionRole::Client, "rpc-reserved-capacity", 1, None),
        ),
        establish_session_v3(
            server_carrier,
            regression_config(
                SessionRole::Server,
                "rpc-reserved-capacity",
                1,
                Some(Arc::new(EchoRpc)),
            ),
        ),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
    let (first, first_incoming) = tokio::join!(
        client.open_stream("capacity-owner", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let first = first.expect("first data stream");
    let first_incoming = first_incoming.expect("first incoming data stream");
    let queued = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .open_stream("queued-data", StreamMetadata::empty())
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
async fn peer_stream_reset_wakes_a_reader_blocked_below_the_session_boundary() {
    let (client_carrier, server_inner) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let server_carrier: Arc<dyn CarrierSessionV3> =
        Arc::new(BlockingApplicationReadCarrierSession {
            inner: server_inner,
            accepts: AtomicU64::new(0),
            block_on: 2,
            enabled: enabled.clone(),
            entered: entered.clone(),
            release: release.clone(),
        });
    let client_config = regression_config(SessionRole::Client, "peer-reset-wakes-read", 1, None);
    let server_config = regression_config(SessionRole::Server, "peer-reset-wakes-read", 1, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client session");
    let server = server.expect("server session");
    let (outgoing, incoming) = tokio::join!(
        client.open_stream("peer-reset-wakes-read", StreamMetadata::empty()),
        server.accept_stream(),
    );
    let outgoing = outgoing.expect("outgoing stream");
    let incoming = incoming.expect("incoming stream");

    enabled.store(true, Ordering::Release);
    let reading = tokio::spawn(async move { incoming.stream().read().await });
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("reader never reached the blocked carrier read");
    outgoing.reset().await.expect("send peer stream reset");

    let error = tokio::time::timeout(Duration::from_millis(250), reading)
        .await
        .expect("peer STREAM_RESET did not wake the blocked reader")
        .expect("join blocked reader")
        .expect_err("peer reset must fail the read");
    assert_eq!(error, SessionError::StreamReset);
    release.notify_one();
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn peer_initiated_rekey_is_bounded_by_the_receivers_completion_deadline() {
    let (client_carrier, server_inner) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let server_carrier: Arc<dyn CarrierSessionV3> =
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
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");
    let (stream, incoming) = tokio::join!(
        client.open_stream("peer-rekey-deadline", StreamMetadata::empty()),
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
    let terminal = tokio::time::timeout(Duration::from_millis(250), server.wait_termination())
        .await
        .expect("peer-initiated rekey ignored the receiver completion deadline");
    assert_eq!(terminal.error, SessionError::Timeout);
    release.notify_one();
    assert!(rekeying.await.expect("join rekey task").is_err());
    let _ = stream.reset().await;
    let _ = incoming.stream().reset().await;
}

#[tokio::test]
async fn close_flush_deadline_also_bounds_carrier_close() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let active_closes = Arc::new(AtomicU64::new(0));
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(HangingCloseCarrierSession {
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
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    let error = tokio::time::timeout(Duration::from_millis(250), client.close())
        .await
        .expect("carrier close escaped the close_flush deadline")
        .expect_err("hanging carrier close must report timeout");
    assert_eq!(error, SessionError::Timeout);
    assert_eq!(active_closes.load(Ordering::Acquire), 0);
    let _ = server.close().await;
}

#[tokio::test]
async fn concurrent_close_waits_for_the_owned_close_workflow() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicU64::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: client_inner,
        enabled: enabled.clone(),
        writes,
        block_on: 1,
        entered: entered.clone(),
        release: release.clone(),
    });
    let mut client_config = regression_config(SessionRole::Client, "concurrent-close", 1, None);
    let mut server_config = regression_config(SessionRole::Server, "concurrent-close", 1, None);
    client_config.deadlines.close_flush = Duration::from_millis(500);
    server_config.deadlines.close_flush = Duration::from_millis(500);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    enabled.store(true, Ordering::Release);
    let first = tokio::spawn({
        let client = client.clone();
        async move { client.close().await }
    });
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("first close did not enter the owned control flush");
    let server_close = tokio::spawn({
        let server = server.clone();
        async move { server.close().await }
    });
    let second = tokio::spawn({
        let client = client.clone();
        async move { client.close().await }
    });
    let mut second = second;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut second)
            .await
            .is_err(),
        "concurrent close returned before the owner completed"
    );
    release.notify_one();
    first.await.expect("join first close").expect("first close");
    second
        .await
        .expect("join second close")
        .expect("second close");
    let _ = server_close.await.expect("join server close");
}

#[tokio::test]
async fn canceled_first_close_leaves_the_owned_workflow_for_later_close() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: client_inner,
        enabled: enabled.clone(),
        writes: Arc::new(AtomicU64::new(0)),
        block_on: 1,
        entered: entered.clone(),
        release: release.clone(),
    });
    let mut client_config = regression_config(SessionRole::Client, "canceled-first-close", 1, None);
    client_config.deadlines.close_flush = Duration::from_millis(500);
    let mut server_config = regression_config(SessionRole::Server, "canceled-first-close", 1, None);
    server_config.deadlines.close_flush = Duration::from_millis(500);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    enabled.store(true, Ordering::Release);
    let first = tokio::spawn({
        let client = client.clone();
        async move { client.close().await }
    });
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("first close did not enter its owned workflow");
    first.abort();
    assert!(first.await.expect_err("aborted first close").is_cancelled());

    let mut second = tokio::spawn({
        let client = client.clone();
        async move { client.close().await }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut second)
            .await
            .is_err(),
        "later close returned before the owned workflow completed"
    );
    release.notify_one();
    tokio::time::timeout(Duration::from_millis(500), &mut second)
        .await
        .expect("later close remained blocked after release")
        .expect("join later close")
        .expect("later close");
    server.close().await.expect("close server");
}

#[tokio::test]
async fn idle_timeout_drops_a_hanging_carrier_close_future() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let active_closes = Arc::new(AtomicU64::new(0));
    let client_carrier: Arc<dyn CarrierSessionV3> = Arc::new(HangingCloseCarrierSession {
        inner: client_inner,
        active_closes: active_closes.clone(),
    });
    let mut client_config = regression_config(SessionRole::Client, "bounded-idle-close", 1, None);
    let server_config = regression_config(SessionRole::Server, "bounded-idle-close", 1, None);
    client_config.idle_timeout = Duration::from_millis(20);
    client_config.deadlines.close_flush = Duration::from_millis(20);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    let termination = tokio::time::timeout(Duration::from_millis(250), client.wait_termination())
        .await
        .expect("idle timeout did not terminate the session");
    assert_eq!(termination.error, SessionError::Timeout);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(active_closes.load(Ordering::Acquire), 0);
    let _ = server.close().await;
}

#[tokio::test]
async fn peer_session_close_flushes_an_authenticated_reply_before_carrier_shutdown() {
    let (client_carrier, server_inner) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicU64::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let server_carrier: Arc<dyn CarrierSessionV3> = Arc::new(BlockingNthWriteCarrierSession {
        inner: server_inner,
        enabled: enabled.clone(),
        writes: writes.clone(),
        block_on: 1,
        entered: entered.clone(),
        release: release.clone(),
    });
    let client_config = regression_config(SessionRole::Client, "peer-close-reply", 1, None);
    let server_config = regression_config(SessionRole::Server, "peer-close-reply", 1, None);
    let (client, server) = tokio::join!(
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    enabled.store(true, Ordering::Release);
    let closing = tokio::spawn({
        let client = client.clone();
        async move { client.close().await }
    });
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("peer SESSION_CLOSE did not trigger an authenticated reply");
    assert_eq!(writes.load(Ordering::Acquire), 1);
    release.notify_one();
    tokio::time::timeout(Duration::from_millis(250), closing)
        .await
        .expect("client close did not finish after the authenticated reply")
        .expect("join client close")
        .expect("client close");
    let termination = tokio::time::timeout(Duration::from_millis(250), server.wait_termination())
        .await
        .expect("peer close reply did not finish session termination");
    assert_eq!(termination.error, SessionError::Closed);
}

#[tokio::test]
async fn local_rekey_waits_for_an_in_flight_inbound_open_responder() {
    let (client_inner, server_carrier) = memory_carrier_pair_for_logical(1);
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_carrier: Arc<dyn CarrierSessionV3> =
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
        establish_session_v3(client_carrier, client_config),
        establish_session_v3(server_carrier, server_config),
    );
    let client = client.expect("client Session");
    let server = server.expect("server Session");

    enabled.store(true, Ordering::Release);
    let opening = {
        let server = server.clone();
        tokio::spawn(async move {
            server
                .open_stream("concurrent-inbound-open", StreamMetadata::empty())
                .await
        })
    };
    tokio::time::timeout(Duration::from_millis(250), entered.notified())
        .await
        .expect("inbound responder never reached the blocked FSS3 read");
    let rekeying = {
        let client = client.clone();
        tokio::spawn(async move { client.rekey().await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !rekeying.is_finished(),
        "rekey bypassed the inbound responder"
    );

    release.notify_one();
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
