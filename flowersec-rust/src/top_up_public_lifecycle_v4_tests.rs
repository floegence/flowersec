use super::*;
use crate::codec_v4::tests::{array, b, encode_map, sign, t, u};
use crate::namespace_v4::verifier::credential::tests::Fixture;
use crate::pool_v4::tests::StoreFixture;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::sync::Semaphore;

const PROFILE: &str = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";

// These are the real host authority callbacks. The source still verifies the
// signed fence, records its durable intent, installs credentials and commits Ack.
#[derive(Debug)]
struct Authority {
    key: Ed25519KeyPair,
    proof_calls: AtomicUsize,
    exchanges: Mutex<Vec<u32>>,
    hold_proof: AtomicBool,
    proof_entered: Semaphore,
    proof_release: Semaphore,
    hold_ack: AtomicBool,
    ack_entered: Semaphore,
    ack_release: Semaphore,
    terminal: Option<TopUpErrorCode>,
    invalid_proof: AtomicBool,
}
impl Authority {
    fn new(terminal: Option<TopUpErrorCode>) -> Arc<Self> {
        Arc::new(Self {
            key: Ed25519KeyPair::from_seed_unchecked(&[74; 32]).unwrap(),
            proof_calls: AtomicUsize::new(0),
            exchanges: Mutex::new(Vec::new()),
            hold_proof: AtomicBool::new(false),
            proof_entered: Semaphore::new(0),
            proof_release: Semaphore::new(0),
            hold_ack: AtomicBool::new(false),
            ack_entered: Semaphore::new(0),
            ack_release: Semaphore::new(0),
            terminal,
            invalid_proof: AtomicBool::new(false),
        })
    }
}
#[async_trait]
impl TopUpFenceProvider for Authority {
    async fn owner_fence_proof(
        &self,
        facts: &TopUpIntent,
        generation: u64,
        _: &CancellationToken,
    ) -> Result<Vec<u8>> {
        self.proof_calls.fetch_add(1, Ordering::AcqRel);
        if self.hold_proof.load(Ordering::Acquire) {
            self.proof_entered.add_permits(1);
            self.proof_release.acquire().await.unwrap().forget();
        }
        let mut wire = sign(
            "OwnerFenceProof",
            &[
                (0, t(&facts.tenant_id)),
                (1, b(&facts.source_incarnation)),
                (2, b(&facts.operation_id)),
                (3, b(&facts.request_digest)),
                (4, u(generation)),
                (5, u(900)),
                (6, u(10000)),
                (7, b(&[1; 16])),
            ],
            &self.key,
        );
        if self.invalid_proof.load(Ordering::Acquire) {
            *wire.last_mut().unwrap() ^= 1;
        }
        Ok(wire)
    }
}
#[async_trait]
impl TopUpControlTransport for Authority {
    async fn exchange(
        &self,
        method: u32,
        wire: &[u8],
        _: &CancellationToken,
    ) -> Result<TopUpExchangeResult> {
        self.exchanges.lock().unwrap().push(method);
        if method == 41007 {
            if self.hold_ack.load(Ordering::Acquire) {
                self.ack_entered.add_permits(1);
                self.ack_release.acquire().await.unwrap().forget();
            }
            return Ok(TopUpExchangeResult::AckConfirmed);
        }
        assert_eq!(method, 41006);
        if let Some(error) = self.terminal {
            return Ok(TopUpExchangeResult::Terminal(failure(error)));
        }
        let request = codec::decode(
            wire,
            "TopUpRequest",
            Limits {
                bytes: 524288,
                nodes: 256,
            },
            None,
        )
        .expect("host receives a complete canonical TopUp request");
        let facts = intent(&projection(request, &[6, 7])?)?;
        let material = b"original-credential";
        let entry = encode_map(&[
            (0, u(1)),
            (1, u(1)),
            (2, u(20000)),
            (3, b(material)),
            (4, b(&Sha256::digest(material))),
            (5, b(&facts.client_identity_digest)),
        ]);
        let mut fields = vec![
            (0, b(&facts.operation_id)),
            (1, t(&facts.tenant_id)),
            (2, b(&facts.source_incarnation)),
            (3, u(1)),
            (4, array(&[entry])),
            (5, u(1)),
            (6, vec![0xf4]),
            (8, vec![0xf5]),
        ];
        let digest = raw_digest(&encode_map(&fields));
        fields.push((9, b(&digest)));
        Ok(TopUpExchangeResult::Response {
            canonical_response: encode_map(&fields),
            replay: false,
        })
    }
}
struct MaterialDecoder {
    bytes: PoolCredentialBytes,
    calls: AtomicUsize,
}
impl fmt::Debug for MaterialDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MaterialDecoder")
    }
}
impl TopUpMaterialDecoder for MaterialDecoder {
    fn decode(&self, encoded: &[u8]) -> Result<PoolCredentialBytes> {
        assert_eq!(encoded, b"original-credential");
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(PoolCredentialBytes {
            artifact: self.bytes.artifact.clone(),
            client_certificate: self.bytes.client_certificate.clone(),
            server_certificate: self.bytes.server_certificate.clone(),
            activation: self.bytes.activation.clone(),
        })
    }
}
struct TestPool {
    environment: crate::TransportEnvironment,
    store: StoreFixture,
    pool: PreauthorizedPoolSource,
    authority: Arc<Authority>,
    decoder: Arc<MaterialDecoder>,
}
impl TestPool {
    fn new(terminal: Option<TopUpErrorCode>, timeout: Duration) -> Self {
        let mut fixture =
            Fixture::with_identity(codec::ActivationSource::PreauthorizedPool, PROFILE, None);
        let identity = fixture.environment.identity_keys(PROFILE).unwrap();
        fixture.set_client_keys(&identity);
        // A pinned signed route supplies the real provider policy required for
        // installation; this test acquires material without opening a carrier.
        fixture.set_wss_route(443, Some([83; 32]));
        let store = StoreFixture::new(&fixture);
        let decoder = Arc::new(MaterialDecoder {
            bytes: PoolCredentialBytes {
                artifact: fixture.artifact.clone(),
                client_certificate: fixture.client.clone(),
                server_certificate: fixture.server.clone(),
                activation: fixture.activation.clone(),
            },
            calls: AtomicUsize::new(0),
        });
        let source = crate::LocalDirectMaterialSource::preauthorized_pool(
            &fixture.environment,
            crate::PreauthorizedPoolSourceConfiguration {
                namespaces: vec![Arc::new(crate::crypto_v4::connect::Namespace::new(
                    fixture.verifier,
                ))],
                identity: identity.clone(),
                credentials: Vec::new(),
                spend_ledger: store.store.clone(),
                provider: crate::WssConnectOptions {
                    binding_mode: crate::BindingMode::DirectExporter,
                    remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
                    origin: None,
                    ca_certificates_der: Vec::new(),
                    timeout: Duration::from_secs(1),
                    publication_timeout: Duration::from_secs(1),
                    queue_messages: 1,
                    prepare_bytes: 65536,
                    native_runtime_bytes: 1 << 20,
                },
                application_profile: crate::ApplicationProfile::Transport,
            },
        )
        .unwrap();
        let authority = Authority::new(terminal);
        let pool = PreauthorizedPoolSource::new(
            source,
            PoolTopUpConfiguration {
                tenant_id: "tenant".into(),
                source_incarnation: [41; 16],
                binding_generation: 1,
                pool_digest: [46; 32],
                identity: Some(identity),
                identity_certificate: Some(fixture.client.clone()),
                fence_authority_key_id: [1; 16],
                fence_authority_public_key: authority.key.public_key().as_ref().try_into().unwrap(),
                operation_lifetime: Duration::from_secs(3),
                call_timeout: timeout,
                proof_provider: authority.clone(),
                control: authority.clone(),
                material_decoder: decoder.clone(),
            },
        )
        .unwrap();
        Self {
            environment: fixture.environment,
            store,
            pool,
            authority,
            decoder,
        }
    }
    async fn close(&self) {
        self.pool.close();
        assert!(
            tokio::time::timeout(
                Duration::from_secs(3),
                self.pool.wait_cleanup(&CancellationToken::new())
            )
            .await
            .unwrap()
            .unwrap()
            .complete
        );
    }
}
impl Drop for TestPool {
    fn drop(&mut self) {
        self.authority.proof_release.add_permits(8);
        self.authority.ack_release.add_permits(8);
        self.pool.close();
    }
}
fn one() -> TopUpOptions {
    TopUpOptions {
        desired_count: 1,
        max_item_bytes: 65536,
    }
}
async fn entered(gate: &Semaphore) {
    tokio::time::timeout(Duration::from_secs(3), gate.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
}

#[tokio::test]
async fn public_top_up_installs_once_then_late_ack_finishes_original_pending_handle() {
    let test = TestPool::new(None, Duration::from_millis(150));
    test.authority.hold_ack.store(true, Ordering::Release);
    let operation = test.pool.top_up(one(), &CancellationToken::new()).await;
    assert_eq!(
        operation.state,
        Some(TopUpState::Installed),
        "{operation:?}"
    );
    assert_eq!(
        operation.call_error,
        Some(failure(TopUpErrorCode::DeadlineExceeded))
    );
    let handle = operation.handle.unwrap();
    entered(&test.authority.ack_entered).await;
    assert!(!handle.cleanup_status().complete);
    assert_eq!(test.decoder.calls.load(Ordering::Acquire), 1);
    let canceled = CancellationToken::new();
    canceled.cancel();
    assert_eq!(
        handle.wait_cleanup(&canceled).await.unwrap_err(),
        failure(TopUpErrorCode::Canceled)
    );
    assert_eq!(
        test.pool.top_up_status(&handle, &canceled).call_error,
        Some(failure(TopUpErrorCode::Canceled))
    );
    assert_eq!(
        test.pool
            .top_up(one(), &CancellationToken::new())
            .await
            .call_error,
        Some(failure(TopUpErrorCode::CapacityExhausted))
    );
    // Restore cannot duplicate credentials already installed in this source.
    assert_eq!(
        test.pool.restore_installed_materials().unwrap_err(),
        failure(TopUpErrorCode::RelinkRequired)
    );
    assert_eq!(
        test.pool.restore_installed_materials().unwrap_err(),
        failure(TopUpErrorCode::RelinkRequired)
    );
    assert_eq!(test.decoder.calls.load(Ordering::Acquire), 3);
    let acquired = test
        .pool
        .acquire(
            &test.environment,
            &crate::ConnectionRequest::default(),
            &CancellationToken::new(),
        )
        .unwrap();
    drop(acquired);
    assert!(matches!(
        test.pool.acquire(
            &test.environment,
            &crate::ConnectionRequest::default(),
            &CancellationToken::new()
        ),
        Err(crate::MaterialSourceError::SourceExhausted)
    ));
    test.pool.restore_installed_materials().unwrap();
    assert_eq!(test.decoder.calls.load(Ordering::Acquire), 3);
    test.authority.ack_release.add_permits(1);
    assert!(
        tokio::time::timeout(
            Duration::from_secs(3),
            handle.wait_cleanup(&CancellationToken::new())
        )
        .await
        .unwrap()
        .unwrap()
        .complete
    );
    let status = test.pool.top_up_status(&handle, &CancellationToken::new());
    assert_eq!(status.state, Some(TopUpState::Acked));
    assert_eq!(status.outcome, Some(TopUpOutcome::Success));
    assert!(status.handle.is_none());
    assert_eq!(*test.authority.exchanges.lock().unwrap(), [41006, 41007]);
    assert_eq!(test.store.rows(), 0, "acquiring material is not a spend");
    let recovered = test
        .pool
        .recover_pending_top_ups("tenant", [41; 16], &CancellationToken::new())
        .await;
    assert!(recovered.call_error.is_none());
    assert_eq!(recovered.operations[0].state, Some(TopUpState::Acked));
    let material_source = test.pool.material_source();
    test.close().await;
    assert!(material_source.is_closed());
}

#[tokio::test]
async fn public_top_up_observer_cancel_keeps_one_original_proof_and_durable_terminal() {
    let test = TestPool::new(
        Some(TopUpErrorCode::TopUpRequestExpired),
        Duration::from_secs(2),
    );
    test.authority.hold_proof.store(true, Ordering::Release);
    let cancel = CancellationToken::new();
    let mut pending = Box::pin(test.pool.top_up(one(), &cancel));
    tokio::select! { _ = entered(&test.authority.proof_entered) => {}, value = &mut pending => panic!("premature {value:?}") }
    cancel.cancel();
    let pending = pending.await;
    assert_eq!(pending.state, Some(TopUpState::Pending));
    assert_eq!(pending.call_error, Some(failure(TopUpErrorCode::Canceled)));
    let handle = pending.handle.unwrap();
    let token = CancellationToken::new();
    let mut joined = Box::pin(test.pool.top_up(TopUpOptions::default(), &token));
    assert!(futures_util::poll!(&mut joined).is_pending());
    assert_eq!(test.authority.proof_calls.load(Ordering::Acquire), 1);
    test.authority.hold_proof.store(false, Ordering::Release);
    test.authority.proof_release.add_permits(1);
    let terminal = joined.await;
    assert_eq!(terminal.options, Some(one()));
    assert_eq!(terminal.state, Some(TopUpState::Terminal));
    assert_eq!(
        terminal.outcome,
        Some(TopUpOutcome::Rejected(failure(
            TopUpErrorCode::TopUpRequestExpired
        )))
    );
    assert_eq!(
        test.pool
            .top_up_status(&handle, &CancellationToken::new())
            .state,
        Some(TopUpState::Terminal)
    );
    let recovered = test
        .pool
        .recover_pending_top_ups("tenant", [41; 16], &CancellationToken::new())
        .await;
    assert!(recovered.call_error.is_none());
    assert_eq!(recovered.operations.len(), 1);
    assert_eq!(recovered.operations[0].state, Some(TopUpState::Terminal));
    test.close().await;
}

#[tokio::test]
async fn public_top_up_recovery_is_finite_and_close_waits_for_original_provider() {
    let test = TestPool::new(
        Some(TopUpErrorCode::SourceUnavailable),
        Duration::from_secs(2),
    );
    let pending = test.pool.top_up(one(), &CancellationToken::new()).await;
    assert_eq!(pending.state, Some(TopUpState::Pending));
    let handle = pending.handle.unwrap();
    test.authority.hold_proof.store(true, Ordering::Release);
    let cancel = CancellationToken::new();
    let mut recovery = Box::pin(
        test.pool
            .recover_pending_top_ups("tenant", [41; 16], &cancel),
    );
    tokio::select! { _ = entered(&test.authority.proof_entered) => {}, _ = &mut recovery => panic!("recovery escaped provider") }
    let conflict = test
        .pool
        .recover_pending_top_ups("tenant", [41; 16], &CancellationToken::new())
        .await;
    assert_eq!(
        conflict.call_error,
        Some(failure(TopUpErrorCode::CapacityExhausted))
    );
    cancel.cancel();
    assert_eq!(
        recovery.await.call_error,
        Some(failure(TopUpErrorCode::Canceled))
    );
    test.pool.close();
    assert!(!test.pool.cleanup_status().complete);
    assert_eq!(
        test.pool.wait_cleanup(&cancel).await.unwrap_err(),
        failure(TopUpErrorCode::Canceled)
    );
    test.authority.proof_release.add_permits(1);
    test.close().await;
    assert_eq!(
        test.pool
            .top_up_status(&handle, &CancellationToken::new())
            .call_error,
        Some(failure(TopUpErrorCode::SourceUnavailable))
    );
}

#[tokio::test]
async fn public_top_up_rejects_invalid_authority_and_foreign_observation_without_control_io() {
    let test = TestPool::new(
        Some(TopUpErrorCode::SourceUnavailable),
        Duration::from_secs(1),
    );
    let canceled = CancellationToken::new();
    canceled.cancel();
    assert_eq!(
        test.pool.top_up(one(), &canceled).await.call_error,
        Some(failure(TopUpErrorCode::Canceled))
    );
    assert_eq!(
        test.pool
            .top_up(
                TopUpOptions {
                    desired_count: 0,
                    ..one()
                },
                &CancellationToken::new()
            )
            .await
            .call_error,
        Some(failure(TopUpErrorCode::SourceContractInvalid))
    );
    assert!(
        test.pool
            .recover_pending_top_ups("tenant", [41; 16], &CancellationToken::new())
            .await
            .operations
            .is_empty()
    );
    assert_eq!(
        test.pool
            .recover_pending_top_ups("other", [41; 16], &CancellationToken::new())
            .await
            .call_error,
        Some(failure(TopUpErrorCode::PermissionDenied))
    );
    assert_eq!(
        test.pool
            .recover_pending_top_ups("tenant", [41; 16], &canceled)
            .await
            .call_error,
        Some(failure(TopUpErrorCode::Canceled))
    );
    test.authority.invalid_proof.store(true, Ordering::Release);
    let pending = test.pool.top_up(one(), &CancellationToken::new()).await;
    assert_eq!(
        pending.call_error,
        Some(failure(TopUpErrorCode::SourceContractInvalid))
    );
    assert!(test.authority.exchanges.lock().unwrap().is_empty());
    let handle = pending.handle.unwrap();
    let foreign = TestPool::new(
        Some(TopUpErrorCode::SourceUnavailable),
        Duration::from_secs(1),
    );
    assert_eq!(
        foreign
            .pool
            .top_up_status(&handle, &CancellationToken::new())
            .call_error,
        Some(failure(TopUpErrorCode::OperationConflict))
    );
    foreign.close().await;
    test.close().await;
}
