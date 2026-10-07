mod notification_delivery_regressions {
    use super::{link, Profile};
    use crate::{MessageCodec, MessageDefinition, NotificationContext, NotificationDropPolicy,
        NotificationPeer, NotificationServiceRegistration, ServiceContract, ServiceError,
        ServiceFailure, ServiceNotificationObserver};
    use crate::codec_v4::tests::{encode_map, t, u};
    use std::{sync::{Arc, Condvar, Mutex}, time::Duration};
    use tokio_util::sync::CancellationToken;

    #[derive(Debug)]
    struct Decoder {
        definition: MessageDefinition,
        entered: Mutex<Vec<u8>>,
        blocked: Mutex<bool>,
        release: Condvar,
        failure: Option<ServiceFailure>,
    }
    impl Decoder {
        fn release(&self) {
            *self.blocked.lock().unwrap() = false;
            self.release.notify_all();
        }
    }
    impl MessageCodec<u8> for Decoder {
        fn definition(&self) -> &MessageDefinition { &self.definition }
        fn encode(&self, value: &u8, destination: &mut [u8]) -> Result<usize, ServiceError> {
            destination[0] = *value; Ok(1)
        }
        fn decode(&self, source: &[u8]) -> Result<u8, ServiceError> {
            self.entered.lock().unwrap().push(source[0]);
            let mut blocked = self.blocked.lock().unwrap();
            while *blocked {
                let waited = self.release.wait_timeout(blocked, Duration::from_secs(5)).unwrap();
                blocked = waited.0;
                if waited.1.timed_out() { return Err(ServiceError(ServiceFailure::DeadlineExceeded)); }
            }
            if source[0] == 1 && let Some(failure) = self.failure { return Err(ServiceError(failure)); }
            Ok(source[0])
        }
    }
    #[derive(Debug, Default)]
    struct Observer { values: Mutex<Vec<(u8, u64)>>, failure: Option<ServiceFailure> }
    #[async_trait::async_trait]
    impl ServiceNotificationObserver<u8> for Observer {
        fn application_bytes(&self) -> u64 { 1024 }
        async fn observe(&self, value: u8, context: NotificationContext) -> Result<(), ServiceError> {
            self.values.lock().unwrap().push((value, context.dropped_before));
            if value == 1 && let Some(failure) = self.failure { return Err(ServiceError(failure)); }
            Ok(())
        }
    }
    fn setup(environment: &crate::TransportEnvironment, client: &crate::Session, server: &crate::Session,
        blocked: bool, failure: Option<ServiceFailure>) -> (NotificationPeer, NotificationPeer, ServiceContract, Arc<Decoder>) {
        let contract = ServiceContract::capture(environment, &encode_map(&[
            (0, t("example/observe")), (1, u(42)), (2, u(2)), (5, u(0)),
            (6, t("bytes.v1")), (7, t("none.v1")), (8, u(0)), (9, u(0)), (10, u(0)),
            (11, u(10000)), (21, vec![0xf4]), (23, u(128)), (27, vec![0x80]),
        ])).unwrap();
        let decoder = Arc::new(Decoder { definition: MessageDefinition::new([9; 32], "bytes.v1".into(), 128).unwrap(),
            entered: Mutex::new(Vec::new()), blocked: Mutex::new(blocked), release: Condvar::new(), failure });
        let registration = NotificationServiceRegistration { contract: contract.clone(), request: decoder.definition.clone(),
            query_allowed: true, offer: None, execution: None, caller: None, handler: None };
        (client.notifications(vec![registration.clone()]).unwrap(), server.notifications(vec![registration]).unwrap(), contract, decoder)
    }
    async fn until(predicate: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !predicate() { tokio::task::yield_now().await; }
        }).await.unwrap();
    }
    async fn publish(peer: &NotificationPeer, contract: &ServiceContract, value: u8) {
        peer.publish_encoded(contract, &[value], Duration::from_secs(5), None, &CancellationToken::new()).await.unwrap();
    }

    #[tokio::test]
    async fn ordinary_keep_latest_replaces_dequeued_input_waiting_for_executor() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client, server, ct, st) = link(&fixture.environment, c, s);
        let (peer, sender, contract, decoder) = setup(&fixture.environment, &client, &server, false, None);
        let observer = Arc::new(Observer::default());
        let subscription = peer.subscribe(contract.clone(), decoder.clone(), NotificationDropPolicy::KeepLatest, observer.clone()).unwrap();
        let group = crate::application_executor_v4::ApplicationGroup::new_local(
            fixture.environment.root().application_services().unwrap(), CancellationToken::new()).unwrap();
        let mut occupied = Vec::new();
        while let Ok(position) = group.try_ordinary(false, None) { occupied.push(position); }
        assert_eq!(occupied.len(), fixture.environment.application_executor_config().running);
        publish(&sender, &contract, 1).await;
        until(|| fixture.environment.root().application_snapshot().ordinary_ready > 0).await;
        publish(&sender, &contract, 2).await;
        until(|| subscription.pending_gap().0 == 1).await;
        assert!(decoder.entered.lock().unwrap().is_empty());
        drop(occupied);
        until(|| observer.values.lock().unwrap().len() == 1).await;
        assert_eq!(*decoder.entered.lock().unwrap(), [2]);
        assert_eq!(*observer.values.lock().unwrap(), [(2, 1)]);
        subscription.close(); assert!(subscription.wait_closed(Duration::from_secs(2)).await.complete);
        peer.close(); sender.close(); client.close(); server.close(); ct.abort(); st.abort();
    }

    #[test]
    fn ordinary_keep_latest_replaces_decoder_waiting_in_blocking_pool() {
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).max_blocking_threads(1).enable_all().build().unwrap().block_on(async {
            let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
            let (client, server, ct, st) = link(&fixture.environment, c, s);
            let (peer, sender, contract, decoder) = setup(&fixture.environment, &client, &server, false, None);
            let observer = Arc::new(Observer::default());
            let subscription = peer.subscribe(contract.clone(), decoder.clone(), NotificationDropPolicy::KeepLatest, observer.clone()).unwrap();
            let (release, held) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || held.recv_timeout(Duration::from_secs(5)).unwrap());
            publish(&sender, &contract, 1).await;
            until(|| fixture.environment.root().application_snapshot().ordinary_running > 0).await;
            publish(&sender, &contract, 2).await;
            until(|| subscription.pending_gap().0 == 1).await;
            assert!(decoder.entered.lock().unwrap().is_empty());
            release.send(()).unwrap(); blocker.await.unwrap();
            until(|| observer.values.lock().unwrap().len() == 1).await;
            assert_eq!(*decoder.entered.lock().unwrap(), [2]);
            assert_eq!(*observer.values.lock().unwrap(), [(2, 1)]);
            subscription.close(); assert!(subscription.wait_closed(Duration::from_secs(2)).await.complete);
            peer.close(); sender.close(); client.close(); server.close(); ct.abort(); st.abort();
        });
    }

    #[tokio::test]
    async fn admitted_decoder_keeps_original_tail_through_keep_latest_and_close() {
        let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
        let (client, server, ct, st) = link(&fixture.environment, c, s);
        let (peer, sender, contract, decoder) = setup(&fixture.environment, &client, &server, true, None);
        let observer = Arc::new(Observer::default());
        let subscription = peer.subscribe(contract.clone(), decoder.clone(), NotificationDropPolicy::KeepLatest, observer.clone()).unwrap();
        publish(&sender, &contract, 1).await;
        until(|| !decoder.entered.lock().unwrap().is_empty()).await;
        publish(&sender, &contract, 2).await; publish(&sender, &contract, 3).await;
        until(|| subscription.pending_gap().0 == 1).await;
        assert_eq!(*decoder.entered.lock().unwrap(), [1]);
        subscription.close(); subscription.close();
        assert!(!subscription.wait_closed(Duration::from_millis(10)).await.complete);
        assert_eq!(fixture.environment.root().application_snapshot().ordinary_running, 1);
        decoder.release();
        assert!(subscription.wait_closed(Duration::from_secs(2)).await.complete);
        assert_eq!(*decoder.entered.lock().unwrap(), [1]);
        assert!(observer.values.lock().unwrap().is_empty());
        peer.close(); sender.close(); client.close(); server.close(); ct.abort(); st.abort();
    }

    #[tokio::test]
    async fn local_closed_and_canceled_errors_preserve_later_notification_delivery() {
        for decode in [false, true] {
            for failure in [ServiceFailure::Closed, ServiceFailure::Canceled] {
                let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_recovery(Profile::X25519);
                let (client, server, ct, st) = link(&fixture.environment, c, s);
                let (peer, sender, contract, decoder) = setup(&fixture.environment, &client, &server, false, decode.then_some(failure));
                let observer = Arc::new(Observer { failure: (!decode).then_some(failure), ..Observer::default() });
                let subscription = peer.subscribe(contract.clone(), decoder.clone(), NotificationDropPolicy::DropNewest, observer.clone()).unwrap();
                publish(&sender, &contract, 1).await;
                until(|| subscription.failure() == Some(ServiceError(failure))).await;
                publish(&sender, &contract, 2).await;
                until(|| observer.values.lock().unwrap().iter().any(|(value, _)| *value == 2)).await;
                assert_eq!(*decoder.entered.lock().unwrap(), [1, 2]);
                subscription.close(); assert!(subscription.wait_closed(Duration::from_secs(2)).await.complete);
                peer.close(); sender.close(); client.close(); server.close(); ct.abort(); st.abort();
            }
        }
    }
}
