mod typed_message_stream_public {
    use super::{Metadata, Profile, link};
    use crate::namespace_v4::verifier::credential::tests::Fixture;
    use crate::transport::ByteStream;
    use crate::{
        BytesMessageCodec, MessageCodec, MessageDefinition, MessageReceiveTerminal,
        MessageStreamDefinition, MessageStreamOptions, ServiceError, ServiceFailure, Session,
        Stream, TypedMessageStream, UTF8MessageCodec,
    };
    use bytes::Bytes;
    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::Semaphore;
    use tokio_util::sync::CancellationToken;

    // The existing fixture performs the authenticated handshake and READY
    // exchange. Only the transport between the two original Sessions is local.
    struct Pair {
        fixture: Fixture,
        client: Session,
        server: Session,
        pumps: [tokio::task::JoinHandle<()>; 2],
    }
    impl Pair {
        fn new() -> Self {
            let (fixture, client, server) =
                crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
            let (client, server, outgoing, incoming) = link(&fixture.environment, client, server);
            Self {
                fixture,
                client,
                server,
                pumps: [outgoing, incoming],
            }
        }
        fn definition(&self) -> MessageStreamDefinition {
            self.fixture
                .environment
                .define_message_stream(
                    "example/messages",
                    "messages.v1",
                    message(41, 32),
                    message(42, 64),
                )
                .unwrap()
        }
        async fn typed_pair(
            &self,
        ) -> (
            TypedMessageStream<Vec<u8>, Vec<u8>>,
            TypedMessageStream<Vec<u8>, Vec<u8>>,
        ) {
            let definition = self.definition();
            let (client, server) = tokio::join!(
                self.client.open_message_stream(
                    definition.clone(),
                    Metadata::empty(),
                    bytes(definition.acceptor_to_opener()),
                    bytes(definition.opener_to_acceptor()),
                    65536,
                    options()
                ),
                async {
                    self.server
                        .next_open()
                        .await
                        .unwrap()
                        .accept_message_stream(
                            definition.clone(),
                            bytes(definition.opener_to_acceptor()),
                            bytes(definition.acceptor_to_opener()),
                            65536,
                            options(),
                        )
                        .unwrap()
                }
            );
            (client.unwrap(), server)
        }
        async fn raw_peer<I: Send + Sync + 'static, O: Send + Sync + 'static>(
            &self,
            definition: MessageStreamDefinition,
            inbound: Arc<dyn MessageCodec<I>>,
            outbound: Arc<dyn MessageCodec<O>>,
            options: MessageStreamOptions,
            receive_window: u64,
        ) -> (TypedMessageStream<I, O>, Stream) {
            let (typed, raw) = tokio::join!(
                async {
                    self.client
                        .open_message_stream(
                            definition,
                            Metadata::empty(),
                            inbound,
                            outbound,
                            65536,
                            options,
                        )
                        .await
                        .expect("public typed OPEN must reach the peer")
                },
                async {
                    let opening = self.server.next_open().await.unwrap();
                    // The hostile peer owns the real typed direction but writes
                    // chosen framing bytes rather than installing a local codec.
                    // The public raw accept correctly refuses this typed OPEN.
                    let candidate = opening.prepare_stream().unwrap();
                    let (stream, read) = candidate.claim_typed().unwrap();
                    drop(read);
                    opening.accept_prepared(stream, receive_window).unwrap()
                }
            );
            (typed, raw)
        }
    }
    impl Drop for Pair {
        fn drop(&mut self) {
            for pump in &self.pumps {
                pump.abort();
            }
            self.client.close();
            self.server.close();
        }
    }
    fn message(tag: u8, maximum: u32) -> MessageDefinition {
        MessageDefinition::new([tag; 32], "bytes.v1".into(), maximum).unwrap()
    }
    fn bytes(definition: &MessageDefinition) -> Arc<BytesMessageCodec> {
        Arc::new(BytesMessageCodec::new(definition.clone()))
    }
    fn options() -> MessageStreamOptions {
        MessageStreamOptions {
            assembly_timeout: Duration::from_millis(150),
            send_timeout: Duration::from_secs(2),
            cleanup_timeout: Duration::from_millis(100),
        }
    }
    fn frame(payload: &[u8]) -> Bytes {
        let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(payload);
        Bytes::from(wire)
    }
    fn typed_metadata(namespace: &str, pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
        use crate::codec_v4::tests::{b, encode_map, t, u};
        let mut values = Vec::new();
        crate::codec_v4::encode_head(&mut values, 5, pairs.len() as u64);
        for (key, value) in pairs {
            values.extend_from_slice(&t(key));
            values.extend_from_slice(&b(value));
        }
        encode_map(&[(0, t(namespace)), (1, u(1)), (2, values)])
    }
    async fn cleanup<I: Send + Sync + 'static, O: Send + Sync + 'static>(
        stream: &TypedMessageStream<I, O>,
    ) {
        stream.close();
        let status = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let status = stream.wait_cleanup().await;
                if status.complete {
                    break status;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(status.pending_callbacks, 0);
        assert!(!status.cleanup_incomplete);
    }
    async fn entered(gate: &Semaphore) {
        tokio::time::timeout(Duration::from_secs(3), gate.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }

    #[tokio::test]
    async fn definition_roundtrip_preserves_direction_and_rejects_noncanonical_or_reserved_input() {
        let pair = Pair::new();
        let original = pair.definition();
        let imported = pair
            .fixture
            .environment
            .import_message_stream_definition(original.canonical())
            .unwrap();
        assert_eq!(imported.kind(), "example/messages");
        assert_eq!(imported.revision(), "messages.v1");
        assert_eq!(imported.digest(), original.digest());
        assert_eq!(imported.canonical(), original.canonical());
        assert_eq!(imported.opener_to_acceptor(), &message(41, 32));
        assert_eq!(imported.acceptor_to_opener(), &message(42, 64));
        let reversed = pair
            .fixture
            .environment
            .define_message_stream(
                "example/messages",
                "messages.v1",
                message(42, 64),
                message(41, 32),
            )
            .unwrap();
        assert_ne!(reversed.digest(), original.digest());
        for invalid in [vec![], vec![0xa0], [original.canonical(), &[0]].concat()] {
            assert_eq!(
                pair.fixture
                    .environment
                    .import_message_stream_definition(&invalid)
                    .unwrap_err()
                    .0,
                ServiceFailure::ContractMismatch
            );
        }
        for kind in [
            "flowersec/messages",
            "flowersec.messages",
            " example/messages",
            "",
        ] {
            assert!(
                pair.fixture
                    .environment
                    .define_message_stream(kind, "messages.v1", message(41, 32), message(42, 64))
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn typed_metadata_accepts_maximum_application_fields_and_enforces_named_schema() {
        let pair = Pair::new();
        let definition = pair.definition();
        let application = Metadata::new(
            "example/metadata",
            1,
            &(0..64)
                .map(|index| (format!("k{index:02}"), Bytes::from(vec![index])))
                .collect(),
        )
        .unwrap();
        let values = [
            ("definition", definition.digest().to_vec()),
            ("application", application.encoded().to_vec()),
        ];
        let wrapper =
            Metadata::from_typed_encoded(&typed_metadata("flowersec/typed-message", &values))
                .unwrap();
        assert_eq!(wrapper.typed_definition(), Some(definition.digest()));
        assert_eq!(
            definition.application_metadata(&wrapper).unwrap().encoded(),
            application.encoded()
        );
        let empty = Metadata::from_typed_encoded(&typed_metadata(
            "flowersec/typed-message",
            &[
                ("definition", definition.digest().to_vec()),
                ("application", Vec::new()),
            ],
        ))
        .unwrap();
        assert!(
            definition
                .application_metadata(&empty)
                .unwrap()
                .encoded()
                .is_empty()
        );
        let mut nested_reserved = application.encoded().to_vec();
        // Construct malformed nested schema through its public ordinary parser
        // boundary, without substituting an alternate transport implementation.
        nested_reserved.push(0);
        let bad_values = [
            vec![("definition", vec![1; 31]), ("application", Vec::new())],
            vec![("definition", vec![1; 33]), ("application", Vec::new())],
            vec![("definition", definition.digest().to_vec())],
            vec![
                ("definition", definition.digest().to_vec()),
                ("unexpected", Vec::new()),
            ],
            vec![
                ("definition", definition.digest().to_vec()),
                ("application", vec![0xa0]),
            ],
            vec![
                ("definition", definition.digest().to_vec()),
                ("application", nested_reserved),
            ],
            vec![
                ("definition", definition.digest().to_vec()),
                ("application", wrapper.encoded().to_vec()),
            ],
        ];
        for values in bad_values {
            assert!(
                Metadata::from_typed_encoded(&typed_metadata("flowersec/typed-message", &values))
                    .is_err(),
                "Invalid typed metadata was accepted: {values:?}"
            );
        }
        assert!(
            Metadata::from_typed_encoded(&typed_metadata("example/typed-message", &values))
                .is_err()
        );
        assert!(Metadata::from_encoded(wrapper.encoded()).is_err());
    }

    #[tokio::test]
    async fn actual_open_preserves_metadata_and_both_codec_directions_after_half_close() {
        let pair = Pair::new();
        let definition = pair.definition();
        let imported = pair
            .fixture
            .environment
            .import_message_stream_definition(definition.canonical())
            .unwrap();
        let mut fields = BTreeMap::from([("cursor".into(), Bytes::from_static(&[0, 255, 3]))]);
        fields.extend((0..63).map(|index| (format!("field{index:02}"), Bytes::from(vec![index]))));
        let application = Metadata::new("example/document", 7, &fields).unwrap();
        let (client, server) = tokio::join!(
            pair.client.open_message_stream(
                definition.clone(),
                application.clone(),
                Arc::new(UTF8MessageCodec::new(
                    definition.acceptor_to_opener().clone()
                )),
                bytes(definition.opener_to_acceptor()),
                65536,
                options()
            ),
            async {
                let opening = pair.server.next_open().await.unwrap();
                assert_eq!(opening.kind(), definition.kind());
                assert_eq!(
                    imported
                        .application_metadata(opening.metadata())
                        .unwrap()
                        .encoded(),
                    application.encoded()
                );
                let wrong = pair
                    .fixture
                    .environment
                    .define_message_stream(
                        "example/messages",
                        "messages.v2",
                        message(41, 32),
                        message(42, 64),
                    )
                    .unwrap();
                assert_eq!(
                    wrong
                        .application_metadata(opening.metadata())
                        .unwrap_err()
                        .0,
                    ServiceFailure::ContractMismatch
                );
                opening
                    .accept_message_stream(
                        imported,
                        bytes(definition.opener_to_acceptor()),
                        Arc::new(UTF8MessageCodec::new(
                            definition.acceptor_to_opener().clone(),
                        )),
                        65536,
                        options(),
                    )
                    .unwrap()
            }
        );
        let client = client.unwrap();
        let cancellation = CancellationToken::new();
        assert_eq!(
            client.application_metadata().encoded(),
            application.encoded()
        );
        assert_eq!(
            server.application_metadata().encoded(),
            application.encoded()
        );
        assert_eq!(client.definition().digest(), definition.digest());
        assert_eq!(
            client
                .send(Arc::new(vec![0, 255, 4]), None, &cancellation)
                .await
                .unwrap(),
            3
        );
        let request = server.receive(None, &cancellation).await.unwrap();
        assert_eq!(request.value.as_deref(), Some([0, 255, 4].as_slice()));
        assert_eq!(request.definition, message(41, 32));
        client.close_write().await.unwrap();
        client.close_write().await.unwrap();
        assert_eq!(
            server.receive(None, &cancellation).await.unwrap().terminal,
            MessageReceiveTerminal::Eof
        );
        assert_eq!(
            client
                .send(Arc::new(vec![8]), None, &cancellation)
                .await
                .unwrap_err()
                .0,
            ServiceFailure::Closed
        );
        assert_eq!(
            server
                .send(Arc::new("response".to_owned()), None, &cancellation)
                .await
                .unwrap(),
            8
        );
        let response = client.receive(None, &cancellation).await.unwrap();
        assert_eq!(response.value.as_deref(), Some("response"));
        assert_eq!(response.definition, message(42, 64));
        server.close_write().await.unwrap();
        assert_eq!(
            client
                .receive_encoded(&cancellation)
                .await
                .unwrap()
                .terminal,
            MessageReceiveTerminal::Eof
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            let (left, right) = tokio::join!(client.finish(), server.finish());
            left.unwrap();
            right.unwrap();
        })
        .await
        .unwrap();
        cleanup(&client).await;
        cleanup(&server).await;
    }

    #[tokio::test]
    async fn rejected_configuration_does_not_consume_a_stream_admission() {
        let pair = Pair::new();
        let definition = pair.definition();
        let invalid = MessageStreamOptions {
            assembly_timeout: Duration::ZERO,
            ..options()
        };
        let error = pair
            .client
            .open_message_stream(
                definition.clone(),
                Metadata::empty(),
                bytes(definition.acceptor_to_opener()),
                bytes(definition.opener_to_acceptor()),
                65536,
                invalid,
            )
            .await
            .unwrap_err();
        assert_eq!(error.0, ServiceFailure::ConfigurationCapacity);
        let error = pair
            .client
            .open_message_stream(
                definition.clone(),
                Metadata::empty(),
                bytes(definition.opener_to_acceptor()),
                bytes(definition.acceptor_to_opener()),
                65536,
                options(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.0, ServiceFailure::ContractMismatch);
        let foreign = Pair::new();
        let other = foreign.definition();
        assert_eq!(
            pair.client
                .open_message_stream(
                    other,
                    Metadata::empty(),
                    bytes(definition.acceptor_to_opener()),
                    bytes(definition.opener_to_acceptor()),
                    65536,
                    options()
                )
                .await
                .unwrap_err()
                .0,
            ServiceFailure::ContractMismatch
        );
        let application = Metadata::new(
            "example/messages",
            1,
            &BTreeMap::from([
                ("a".into(), Bytes::from(vec![1; 1024])),
                ("b".into(), Bytes::from(vec![2; 1024])),
                ("c".into(), Bytes::from(vec![3; 1024])),
                ("d".into(), Bytes::from(vec![4; 921])),
            ]),
        )
        .unwrap();
        assert!(application.encoded().len() > 4006);
        assert_eq!(
            pair.client
                .open_message_stream(
                    definition.clone(),
                    application,
                    bytes(definition.acceptor_to_opener()),
                    bytes(definition.opener_to_acceptor()),
                    65536,
                    options()
                )
                .await
                .unwrap_err()
                .0,
            ServiceFailure::ConfigurationCapacity
        );
        let (client, server) = pair.typed_pair().await;
        client
            .send(Arc::new(vec![7]), None, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            server
                .receive_encoded(&CancellationToken::new())
                .await
                .unwrap()
                .payload
                .unwrap()
                .as_ref(),
            &[7]
        );
        cleanup(&client).await;
        cleanup(&server).await;
    }

    #[tokio::test]
    async fn encoded_receive_preserves_empty_messages_and_fragmented_input_after_observer_cancel() {
        let pair = Pair::new();
        let definition = pair.definition();
        let (client, raw) = pair
            .raw_peer(
                definition.clone(),
                bytes(definition.acceptor_to_opener()),
                bytes(definition.opener_to_acceptor()),
                options(),
                65536,
            )
            .await;
        raw.write(Bytes::from_static(&[0, 0])).await.unwrap();
        let canceled = CancellationToken::new();
        let mut receive = Box::pin(client.receive_encoded(&canceled));
        assert!(futures_util::poll!(&mut receive).is_pending());
        assert_eq!(
            client
                .receive_encoded(&CancellationToken::new())
                .await
                .unwrap_err()
                .0,
            ServiceFailure::ResultModeConflict
        );
        canceled.cancel();
        assert_eq!(receive.await.unwrap_err().0, ServiceFailure::Canceled);
        raw.write(Bytes::from_static(&[0, 0, 0, 0, 0, 3, 7, 8, 9]))
            .await
            .unwrap();
        raw.close_write().await.unwrap();
        let cancellation = CancellationToken::new();
        let empty = client.receive_encoded(&cancellation).await.unwrap();
        assert_eq!(empty.payload, Some(Bytes::new()));
        assert_eq!(empty.definition, message(42, 64));
        let next = client.receive_encoded(&cancellation).await.unwrap();
        assert_eq!(next.payload.unwrap(), Bytes::from_static(&[7, 8, 9]));
        assert_eq!(
            client
                .receive_encoded(&cancellation)
                .await
                .unwrap()
                .terminal,
            MessageReceiveTerminal::Eof
        );
        cleanup(&client).await;
    }

    #[tokio::test]
    async fn framing_failures_reset_only_the_affected_stream() {
        for wire in [vec![0, 0], vec![0, 0, 0, 3, 1], vec![0, 0, 0, 65]] {
            let pair = Pair::new();
            let definition = pair.definition();
            let (client, raw) = pair
                .raw_peer(
                    definition.clone(),
                    bytes(definition.acceptor_to_opener()),
                    bytes(definition.opener_to_acceptor()),
                    options(),
                    65536,
                )
                .await;
            raw.write(Bytes::from(wire)).await.unwrap();
            raw.close_write().await.unwrap();
            let result = client.receive_encoded(&CancellationToken::new()).await;
            if let Err(error) = result {
                assert_eq!(error.0, ServiceFailure::Closed);
            }
            let terminal = client
                .receive_encoded(&CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(terminal.terminal, MessageReceiveTerminal::FramingFailed);
            assert!(terminal.payload.is_none());
            cleanup(&client).await;
            let (left, right) = pair.typed_pair().await;
            left.send(Arc::new(vec![9]), None, &CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(
                right
                    .receive(None, &CancellationToken::new())
                    .await
                    .unwrap()
                    .value,
                Some(vec![9])
            );
            cleanup(&left).await;
            cleanup(&right).await;
        }
    }

    #[tokio::test]
    async fn partial_frame_assembly_deadline_survives_cancellation_of_the_wait() {
        let pair = Pair::new();
        let definition = pair.definition();
        let (client, raw) = pair
            .raw_peer(
                definition.clone(),
                bytes(definition.acceptor_to_opener()),
                bytes(definition.opener_to_acceptor()),
                options(),
                65536,
            )
            .await;
        raw.write(Bytes::from_static(&[0, 0, 0, 3, 7]))
            .await
            .unwrap();
        let canceled = CancellationToken::new();
        let mut waiting = Box::pin(client.receive_encoded(&canceled));
        assert!(futures_util::poll!(&mut waiting).is_pending());
        canceled.cancel();
        assert_eq!(waiting.await.unwrap_err().0, ServiceFailure::Canceled);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            client.receive_encoded(&CancellationToken::new()),
        )
        .await
        .unwrap();
        if let Err(error) = result {
            assert_eq!(error.0, ServiceFailure::Closed);
        }
        assert_eq!(
            client
                .receive_encoded(&CancellationToken::new())
                .await
                .unwrap()
                .terminal,
            MessageReceiveTerminal::AssemblyTimeout
        );
        cleanup(&client).await;
    }

    #[derive(Debug)]
    struct HeldCodec {
        definition: MessageDefinition,
        hold_encode: bool,
        hold_decode: bool,
        entered: Semaphore,
        released: Mutex<bool>,
        changed: Condvar,
        calls: AtomicUsize,
    }
    impl HeldCodec {
        fn new(definition: MessageDefinition, encode: bool, decode: bool) -> Arc<Self> {
            Arc::new(Self {
                definition,
                hold_encode: encode,
                hold_decode: decode,
                entered: Semaphore::new(0),
                released: Mutex::new(false),
                changed: Condvar::new(),
                calls: AtomicUsize::new(0),
            })
        }
        fn hold(&self) -> Result<(), ServiceError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.entered.add_permits(1);
            let blocked = self.released.lock().unwrap();
            let waited = self
                .changed
                .wait_timeout_while(blocked, Duration::from_secs(5), |released| !*released)
                .unwrap();
            if !*waited.0 {
                return Err(ServiceError(ServiceFailure::DeadlineExceeded));
            }
            Ok(())
        }
        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }
    impl MessageCodec<Vec<u8>> for HeldCodec {
        fn definition(&self) -> &MessageDefinition {
            &self.definition
        }
        fn application_bytes(&self) -> u64 {
            1024
        }
        fn encode(&self, value: &Vec<u8>, destination: &mut [u8]) -> Result<usize, ServiceError> {
            if self.hold_encode {
                self.hold()?;
            }
            BytesMessageCodec::new(self.definition.clone()).encode(value, destination)
        }
        fn decode(&self, source: &[u8]) -> Result<Vec<u8>, ServiceError> {
            if self.hold_decode {
                self.hold()?;
            }
            Ok(source.to_vec())
        }
    }

    #[tokio::test]
    async fn canceled_decode_observer_keeps_one_callback_and_cannot_switch_to_encoded_mode() {
        let pair = Pair::new();
        let definition = pair.definition();
        let codec = HeldCodec::new(definition.acceptor_to_opener().clone(), false, true);
        let (client, raw) = pair
            .raw_peer(
                definition.clone(),
                codec.clone(),
                bytes(definition.opener_to_acceptor()),
                options(),
                65536,
            )
            .await;
        raw.write(frame(b"original")).await.unwrap();
        let cancellation = CancellationToken::new();
        let reading = tokio::spawn({
            let client = client.clone();
            let cancellation = cancellation.clone();
            async move { client.receive(None, &cancellation).await }
        });
        entered(&codec.entered).await;
        cancellation.cancel();
        assert_eq!(
            reading.await.unwrap().unwrap_err().0,
            ServiceFailure::Canceled
        );
        assert_eq!(
            client
                .receive_encoded(&CancellationToken::new())
                .await
                .unwrap_err()
                .0,
            ServiceFailure::ResultModeConflict
        );
        codec.release();
        assert_eq!(
            client
                .receive(None, &CancellationToken::new())
                .await
                .unwrap()
                .value,
            Some(b"original".to_vec())
        );
        assert_eq!(codec.calls.load(Ordering::Acquire), 1);
        cleanup(&client).await;
    }

    #[tokio::test]
    async fn close_preserves_the_entered_decoder_until_its_physical_return() {
        let pair = Pair::new();
        let definition = pair.definition();
        let codec = HeldCodec::new(definition.acceptor_to_opener().clone(), false, true);
        let (client, raw) = pair
            .raw_peer(
                definition.clone(),
                codec.clone(),
                bytes(definition.opener_to_acceptor()),
                options(),
                65536,
            )
            .await;
        raw.write(frame(b"held")).await.unwrap();
        let reading = tokio::spawn({
            let client = client.clone();
            async move { client.receive(None, &CancellationToken::new()).await }
        });
        entered(&codec.entered).await;
        client.close();
        let pending = client.wait_cleanup().await;
        assert!(!pending.complete);
        assert!(pending.pending_callbacks >= 1);
        assert_eq!(codec.calls.load(Ordering::Acquire), 1);
        codec.release();
        let _ = reading.await.unwrap();
        cleanup(&client).await;
        let terminal = client
            .receive(None, &CancellationToken::new())
            .await
            .unwrap();
        assert!(terminal.value.is_none());
        assert_eq!(terminal.terminal, MessageReceiveTerminal::Closed);
    }

    #[tokio::test]
    async fn canceled_and_timed_out_send_waits_cannot_refund_a_running_encoder() {
        for timeout in [false, true] {
            let pair = Pair::new();
            let definition = pair.definition();
            let codec = HeldCodec::new(definition.opener_to_acceptor().clone(), true, false);
            let config = MessageStreamOptions {
                send_timeout: Duration::from_millis(100),
                ..options()
            };
            let (client, _raw) = pair
                .raw_peer(
                    definition.clone(),
                    bytes(definition.acceptor_to_opener()),
                    codec.clone(),
                    config,
                    65536,
                )
                .await;
            let cancellation = CancellationToken::new();
            let sending = tokio::spawn({
                let client = client.clone();
                let cancellation = cancellation.clone();
                async move {
                    client
                        .send(Arc::new(vec![1, 2, 3]), None, &cancellation)
                        .await
                }
            });
            entered(&codec.entered).await;
            if !timeout {
                cancellation.cancel();
            }
            let error = sending.await.unwrap().unwrap_err();
            assert_eq!(
                error.0,
                if timeout {
                    ServiceFailure::DeadlineExceeded
                } else {
                    ServiceFailure::Canceled
                }
            );
            client.close();
            let pending = client.wait_cleanup().await;
            assert!(!pending.complete);
            assert!(pending.pending_callbacks >= 1);
            codec.release();
            cleanup(&client).await;
            assert_eq!(codec.calls.load(Ordering::Acquire), 1);
        }
    }

    #[tokio::test]
    async fn bounded_send_admission_refuses_a_fifth_original_job() {
        let pair = Pair::new();
        let definition = pair.definition();
        let codec = HeldCodec::new(definition.opener_to_acceptor().clone(), true, false);
        let (client, raw) = pair
            .raw_peer(
                definition.clone(),
                bytes(definition.acceptor_to_opener()),
                codec.clone(),
                options(),
                65536,
            )
            .await;
        let cancellation = CancellationToken::new();
        let mut jobs = Vec::new();
        for value in 1..=4 {
            let mut job = Box::pin(client.send(Arc::new(vec![value]), None, &cancellation));
            assert!(futures_util::poll!(&mut job).is_pending());
            jobs.push(job);
        }
        entered(&codec.entered).await;
        assert_eq!(
            client
                .send(Arc::new(vec![5]), None, &cancellation)
                .await
                .unwrap_err()
                .0,
            ServiceFailure::ResourceExhausted
        );
        codec.release();
        for job in jobs {
            assert_eq!(job.await.unwrap(), 1);
        }
        let mut observed = Vec::new();
        while observed.len() < 20 {
            observed.extend_from_slice(&raw.read().await.unwrap().unwrap());
        }
        assert_eq!(
            observed,
            [frame(&[1]), frame(&[2]), frame(&[3]), frame(&[4])].concat()
        );
        cleanup(&client).await;
    }

    #[tokio::test]
    async fn strict_utf8_decode_resets_stream_without_scanning_the_next_prefix() {
        let pair = Pair::new();
        let definition = pair.definition();
        let (client, raw) = pair
            .raw_peer(
                definition.clone(),
                Arc::new(UTF8MessageCodec::new(
                    definition.acceptor_to_opener().clone(),
                )),
                bytes(definition.opener_to_acceptor()),
                options(),
                65536,
            )
            .await;
        let cancellation = CancellationToken::new();
        assert_eq!(
            client
                .send(Arc::new(vec![1; 33]), None, &cancellation)
                .await
                .unwrap_err()
                .0,
            ServiceFailure::EncodeFailed
        );
        assert_eq!(
            client
                .send(Arc::new(vec![8]), None, &cancellation)
                .await
                .unwrap(),
            1
        );
        assert_eq!(raw.read().await.unwrap().unwrap(), frame(&[8]));
        raw.write([frame(&[0xff]), frame(b"valid")].concat().into())
            .await
            .unwrap();
        assert_eq!(
            client.receive(None, &cancellation).await.unwrap_err().0,
            ServiceFailure::DecodeFailed
        );
        let terminal = client.receive(None, &cancellation).await.unwrap();
        assert_eq!(terminal.terminal, MessageReceiveTerminal::DecodeFailed);
        assert!(
            terminal.value.is_none(),
            "Structural failure must not disclose the following valid message"
        );
        let encoded = client.receive_encoded(&cancellation).await.unwrap();
        assert_eq!(encoded.terminal, MessageReceiveTerminal::DecodeFailed);
        assert!(encoded.payload.is_none());
        assert_eq!(
            raw.read_result(64).await.unwrap().stream_status,
            crate::ReadStreamStatus::Aborted
        );
        cleanup(&client).await;
    }

    struct ApplicationDecoder {
        definition: MessageDefinition,
        calls: AtomicUsize,
        panic: bool,
    }
    impl MessageCodec<Vec<u8>> for ApplicationDecoder {
        fn definition(&self) -> &MessageDefinition {
            &self.definition
        }
        fn application_bytes(&self) -> u64 {
            1024
        }
        fn encode(&self, value: &Vec<u8>, destination: &mut [u8]) -> Result<usize, ServiceError> {
            BytesMessageCodec::new(self.definition.clone()).encode(value, destination)
        }
        fn decode(&self, source: &[u8]) -> Result<Vec<u8>, ServiceError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if source == [0xff] {
                assert!(!self.panic, "application decoder rejected its own message");
                return Err(ServiceError(ServiceFailure::DecodeFailed));
            }
            Ok(source.to_vec())
        }
    }

    struct ReturnObservedCodec {
        decoder: ApplicationDecoder,
        context: Mutex<Option<crate::ApplicationInvocationContext>>,
    }
    impl MessageCodec<Vec<u8>> for ReturnObservedCodec {
        fn definition(&self) -> &MessageDefinition {
            self.decoder.definition()
        }
        fn application_bytes(&self) -> u64 {
            self.decoder.application_bytes()
        }
        fn encode(&self, value: &Vec<u8>, destination: &mut [u8]) -> Result<usize, ServiceError> {
            self.decoder.encode(value, destination)
        }
        fn decode(&self, source: &[u8]) -> Result<Vec<u8>, ServiceError> {
            self.decoder.decode(source)
        }
        fn decode_with_context(
            &self,
            source: &[u8],
            context: &crate::ApplicationInvocationContext,
        ) -> Result<Vec<u8>, ServiceError> {
            context.check_cancellation()?;
            *self.context.lock().unwrap() = Some(context.clone());
            self.decode(source)
        }
    }

    #[tokio::test]
    async fn decoder_result_waits_for_original_input_and_executor_release() {
        for outcome in 0..3 {
            let pair = Pair::new();
            let definition = pair.definition();
            let codec = Arc::new(ReturnObservedCodec {
                decoder: ApplicationDecoder {
                    definition: definition.acceptor_to_opener().clone(),
                    calls: AtomicUsize::new(0),
                    panic: outcome == 2,
                },
                context: Mutex::new(None),
            });
            let (client, raw) = pair
                .raw_peer(
                    definition.clone(),
                    codec.clone(),
                    bytes(definition.opener_to_acceptor()),
                    options(),
                    65536,
                )
                .await;
            let returned = HeldCodec::new(definition.acceptor_to_opener().clone(), false, false);
            client.set_decode_return_hook(Arc::new({
                let returned = returned.clone();
                move || {
                    returned
                        .hold()
                        .expect("release the original decoder return")
                }
            }));
            let first = if outcome == 0 {
                b"first".as_slice()
            } else {
                &[0xff]
            };
            raw.write([frame(first), frame(b"following")].concat().into())
                .await
                .unwrap();
            let cancellation = CancellationToken::new();
            let mut receiving = Box::pin(client.receive(None, &cancellation));
            tokio::select! {
                _ = entered(&returned.entered) => {},
                _ = &mut receiving => panic!("Decoder result escaped before original input and executor release"),
            }
            let original_context = codec.context.lock().unwrap().clone().unwrap();
            assert!(original_context.check_cancellation().is_ok());
            // The real callback has returned, but the original frame and
            // execution position are deliberately still held at this boundary.
            assert!(
                futures_util::poll!(&mut receiving).is_pending(),
                "Decoder result escaped before original input and executor release"
            );
            assert_eq!(codec.decoder.calls.load(Ordering::Acquire), 1);
            assert_eq!(
                client.receive_encoded(&cancellation).await.unwrap_err().0,
                ServiceFailure::ResultModeConflict
            );
            returned.release();
            let first_result = receiving.await;
            if outcome == 0 {
                assert_eq!(first_result.unwrap().value.as_deref(), Some(first));
            } else {
                assert_eq!(first_result.unwrap_err().0, ServiceFailure::DecodeFailed);
            }
            assert!(original_context.check_cancellation().is_err());
            assert_eq!(
                client.receive(None, &cancellation).await.unwrap().value,
                Some(b"following".to_vec())
            );
            assert_eq!(codec.decoder.calls.load(Ordering::Acquire), 2);
            cleanup(&client).await;
        }
    }

    #[tokio::test]
    async fn application_decode_failure_or_panic_consumes_only_its_original_message() {
        for panic in [false, true] {
            let pair = Pair::new();
            let definition = pair.definition();
            let codec = Arc::new(ApplicationDecoder {
                definition: definition.acceptor_to_opener().clone(),
                calls: AtomicUsize::new(0),
                panic,
            });
            let (client, raw) = pair
                .raw_peer(
                    definition.clone(),
                    codec.clone(),
                    bytes(definition.opener_to_acceptor()),
                    options(),
                    65536,
                )
                .await;
            raw.write([frame(&[0xff]), frame(b"valid")].concat().into())
                .await
                .unwrap();
            let cancellation = CancellationToken::new();
            assert_eq!(
                client.receive(None, &cancellation).await.unwrap_err().0,
                ServiceFailure::DecodeFailed
            );
            assert_eq!(codec.calls.load(Ordering::Acquire), 1);
            assert_eq!(
                client.receive(None, &cancellation).await.unwrap().value,
                Some(b"valid".to_vec())
            );
            assert_eq!(codec.calls.load(Ordering::Acquire), 2);
            cleanup(&client).await;
        }
    }
}
