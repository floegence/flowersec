// These tests use original READY record owners and the normal public Stream
// API.  The bridge's source and destination belong to the same server Session;
// the two client endpoints model independent callers of that server.
#[tokio::test]
async fn duplex_bridge_half_closes_one_direction_and_keeps_reverse_traffic() {
    let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let (left, a) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (right, b) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (left, right) = (left.unwrap(), right.unwrap());
    let bridge = crate::DuplexBridge::new(a.clone(), b.clone(), crate::DuplexBridgeOptions::default()).unwrap();
    assert!(a.read_owner().is_none());
    assert!(b.write(Bytes::from_static(b"alias")).await.is_err());
    bridge.start().unwrap();
    bridge.start().unwrap();
    left.write(Bytes::from_static(b"request")).await.unwrap();
    left.close_write().await.unwrap();
    assert_eq!(right.read_result(64).await.unwrap().data, Bytes::from_static(b"request"));
    assert_eq!(right.read_result(64).await.unwrap().stream_status, ReadStreamStatus::Eof);
    right.write(Bytes::from_static(b"response")).await.unwrap();
    right.close_write().await.unwrap();
    assert_eq!(left.read_result(64).await.unwrap().data, Bytes::from_static(b"response"));
    assert_eq!(left.read_result(64).await.unwrap().stream_status, ReadStreamStatus::Eof);
    let result = tokio::time::timeout(Duration::from_secs(5), bridge.wait()).await.unwrap().unwrap();
    assert_eq!(result.outcome, crate::DuplexOutcome::Normal);
    assert_eq!(result.a_to_b.source_read_bytes, 7);
    assert_eq!(result.a_to_b.destination_accepted_bytes, 7);
    assert_eq!(result.b_to_a.source_read_bytes, 8);
    assert!(result.a_to_b.finish_complete && result.b_to_a.finish_complete);
    assert!(result.cleanup.complete);
    assert!(bridge.progress().transfer_sealed);
    client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn duplex_bridge_rejects_alias_without_claiming_either_stream() {
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let (remote, stream) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let remote = remote.unwrap();
    let error = crate::DuplexBridge::new(stream.clone(), stream.clone(), crate::DuplexBridgeOptions::default()).unwrap_err();
    assert_eq!(error.reason, crate::DuplexBridgeErrorReason::SameEndpoint);
    assert!(stream.read_owner().is_some());
    remote.write(Bytes::from_static(b"untouched")).await.unwrap();
    assert_eq!(stream.read_result(64).await.unwrap().data, Bytes::from_static(b"untouched"));
    drop(remote); drop(stream); client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn duplex_bridge_canceled_wait_does_not_cancel_owner_and_abort_preserves_tail() {
    let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let (left, a) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    // A one-byte peer receive limit forces partial original write acceptance.
    let (right, b) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 1), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (left, right) = (left.unwrap(), right.unwrap());
    let bridge = crate::DuplexBridge::new(a, b, crate::DuplexBridgeOptions::default()).unwrap();
    bridge.start().unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(1), bridge.wait()).await.is_err());
    left.write(Bytes::from_static(b"tail")).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let progress = bridge.progress();
            if progress.a_to_b.destination_accepted_bytes == 1 {
                assert_eq!(progress.a_to_b.source_read_bytes, 4);
                assert_eq!(progress.a_to_b.unaccepted_tail, Bytes::from_static(b"ail"));
                break;
            }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    bridge.abort();
    let error = tokio::time::timeout(Duration::from_secs(5), bridge.wait()).await.unwrap().unwrap_err();
    assert_eq!(error.progress.a_to_b.source_read_bytes, 4);
    assert_eq!(error.progress.a_to_b.destination_accepted_bytes, 1);
    assert_eq!(error.progress.a_to_b.unaccepted_tail, Bytes::from_static(b"ail"));
    let repeated = bridge.wait().await.unwrap_err();
    assert_eq!(error.progress.a_to_b, repeated.progress.a_to_b);
    assert_eq!(error.progress.first_error, None);
    drop(left); drop(right); client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn duplex_bridge_owner_claim_failure_keeps_other_stream_available() {
    let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let (left, a) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (right, b) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let reader = b.read_owner().unwrap().acquire().unwrap();
    let error = crate::DuplexBridge::new(a.clone(), b.clone(), crate::DuplexBridgeOptions::default()).unwrap_err();
    assert_eq!(error.reason, crate::DuplexBridgeErrorReason::OwnerUnavailable);
    assert!(a.read_owner().unwrap().acquire().is_ok());
    drop(reader); drop(left); drop(right); drop(a); drop(b);
    client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn duplex_bridge_refuses_a_pending_prepared_write_before_source_consumption() {
    let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let (left, a) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (right, b) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let write = crate::WriteOperation::prepare(Arc::new(a.clone()), Bytes::from_static(b"prepared"));
    let error = crate::DuplexBridge::new(a.clone(), b.clone(), crate::DuplexBridgeOptions::default()).unwrap_err();
    assert_eq!(error.reason, crate::DuplexBridgeErrorReason::OwnerUnavailable);
    write.cancel();
    assert!(write.cleanup_status().complete);
    let bridge = crate::DuplexBridge::new(a, b, crate::DuplexBridgeOptions::default()).unwrap();
    bridge.abort();
    let _ = bridge.wait().await;
    drop(left); drop(right); client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn duplex_bridge_deadline_applies_before_start_and_preserves_zero_progress() {
    let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let (left, a) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (right, b) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let bridge = crate::DuplexBridge::new(a, b, crate::DuplexBridgeOptions {
        overall_timeout: Duration::from_millis(1), ..crate::DuplexBridgeOptions::default()
    }).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), bridge.wait()).await.unwrap().unwrap_err();
    assert_eq!(error.progress.first_error, Some(SessionError::Timeout));
    assert_eq!(error.progress.a_to_b.source_read_bytes, 0);
    assert_eq!(error.progress.b_to_a.destination_accepted_bytes, 0);
    assert!(bridge.start().is_err());
    drop(left); drop(right); client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn duplex_bridge_replenishes_only_its_original_bounded_receive_window() {
    let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let (left, a) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (right, b) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (left, right) = (left.unwrap(), right.unwrap());
    let bridge = crate::DuplexBridge::new(a, b, crate::DuplexBridgeOptions::default()).unwrap();
    bridge.start().unwrap();
    let payload = Bytes::from(vec![0x5a; 80 * 1024]);
    let write = crate::WriteOperation::prepare(Arc::new(left.clone()), payload.clone());
    let (_, copied) = tokio::join!(async {
        write.start().await.unwrap();
        assert_eq!(write.wait().await.unwrap().accepted_bytes, payload.len() as u64);
        left.close_write().await.unwrap();
    }, async {
        let mut copied = 0u64;
        loop {
            let read = right.read_result(16 * 1024).await.unwrap();
            assert!(read.data.iter().all(|byte| *byte == 0x5a));
            copied += read.data.len() as u64;
            if read.stream_status == ReadStreamStatus::Eof { break; }
            right.grant_receive_limit(copied + 65536).unwrap();
        }
        right.close_write().await.unwrap();
        copied
    });
    assert_eq!(copied, payload.len() as u64);
    assert_eq!(left.read_result(16).await.unwrap().stream_status, ReadStreamStatus::Eof);
    let result = tokio::time::timeout(Duration::from_secs(5), bridge.wait()).await.unwrap().unwrap();
    assert_eq!(result.a_to_b.source_read_bytes, copied);
    assert_eq!(result.a_to_b.destination_accepted_bytes, copied);
    assert!(result.a_to_b.unaccepted_tail.is_empty());
    client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn duplex_bridge_short_cleanup_wait_observes_without_stopping_prepared_operation() {
    let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let (left, a) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (right, b) = tokio::join!(client.open_stream("bridge", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let bridge = crate::DuplexBridge::new(a, b, crate::DuplexBridgeOptions::default()).unwrap();
    assert!(bridge.wait_cleanup(Duration::ZERO).await.cleanup_incomplete);
    assert!(!bridge.cleanup_status().cleanup_incomplete);
    bridge.start().unwrap();
    bridge.abort();
    let error = bridge.wait().await.unwrap_err();
    assert_eq!(error.progress.first_error, None);
    assert_eq!(error.progress.a_to_b.source_read_bytes, 0);
    drop(left); drop(right); client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn native_tcp_duplex_bridge_preserves_real_half_close_and_completion_guarantees() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (native, peer) = tokio::join!(crate::NativeTcpDuplex::connect(&fixture.environment,
        listener.local_addr().unwrap(), crate::NativeTcpDuplexOptions::default()), listener.accept());
    let native = native.unwrap();
    let observer = native.clone();
    assert!(native.info().sdk_owned_socket && native.info().half_close);
    assert!(!native.info().authenticated_send_drain && !native.info().kernel_queue_hard_bound);
    let (remote, stream) = tokio::join!(client.open_stream("tcp", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let remote = remote.unwrap();
    let bridge = crate::DuplexBridge::with_native_tcp(stream.clone(), native, crate::DuplexBridgeOptions::default()).unwrap();
    assert!(stream.read_owner().is_none());
    assert_eq!(observer.close().unwrap_err(), crate::NativeTcpDuplexError::OwnerUnavailable);
    let mut peer = peer.unwrap().0;
    bridge.start().unwrap();
    remote.write(Bytes::from_static(b"request")).await.unwrap();
    remote.close_write().await.unwrap();
    let mut request = Vec::new();
    peer.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"request");
    // Native read EOF does not require closing its still-live write half.
    peer.write_all(b"response").await.unwrap();
    peer.shutdown().await.unwrap();
    assert_eq!(remote.read_result(64).await.unwrap().data, Bytes::from_static(b"response"));
    assert_eq!(remote.read_result(64).await.unwrap().stream_status, ReadStreamStatus::Eof);
    let result = tokio::time::timeout(Duration::from_secs(5), bridge.wait()).await.unwrap().unwrap();
    assert_eq!(result.a_to_b.send_completion, Some(crate::DuplexSendCompletion::NativeTcpWriteShutdownQueued));
    assert_eq!(result.b_to_a.send_completion, Some(crate::DuplexSendCompletion::AuthenticatedStreamDrained));
    assert_eq!(result.a_to_b.destination_accepted_bytes, 7);
    assert_eq!(result.b_to_a.source_read_bytes, 8);
    assert!(result.cleanup.complete);
    assert!(observer.cleanup_status().complete);
    client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn native_tcp_duplex_second_claim_refuses_before_consuming_other_stream() {
    let (fixture, c, s) = crate::crypto_v4::tests::record_pair_for_bridge(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (native, peer) = tokio::join!(crate::NativeTcpDuplex::connect(&fixture.environment,
        listener.local_addr().unwrap(), crate::NativeTcpDuplexOptions::default()), listener.accept());
    let native = native.unwrap();
    let alias = native.clone();
    let (left, a) = tokio::join!(client.open_stream("tcp", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let (right, b) = tokio::join!(client.open_stream("tcp", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let bridge = crate::DuplexBridge::with_native_tcp(a, native, crate::DuplexBridgeOptions::default()).unwrap();
    let error = crate::DuplexBridge::with_native_tcp(b.clone(), alias, crate::DuplexBridgeOptions::default()).unwrap_err();
    assert_eq!(error.reason, crate::DuplexBridgeErrorReason::OwnerUnavailable);
    assert_eq!(error.progress.a_to_b.source_read_bytes, 0);
    assert!(b.read_owner().unwrap().acquire().is_ok());
    bridge.abort(); let _ = bridge.wait().await;
    drop(peer); drop(left); drop(right); drop(b);
    client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn native_tcp_duplex_busy_stream_refusal_leaves_native_owner_available() {
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (native, peer) = tokio::join!(crate::NativeTcpDuplex::connect(&fixture.environment,
        listener.local_addr().unwrap(), crate::NativeTcpDuplexOptions::default()), listener.accept());
    let native = native.unwrap();
    let observer = native.clone();
    let (remote, stream) = tokio::join!(client.open_stream("tcp", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let reader = stream.read_owner().unwrap().acquire().unwrap();
    assert_eq!(crate::DuplexBridge::with_native_tcp(stream.clone(), native, crate::DuplexBridgeOptions::default())
        .unwrap_err().reason, crate::DuplexBridgeErrorReason::OwnerUnavailable);
    drop(reader);
    let bridge = crate::DuplexBridge::with_native_tcp(stream, observer.clone(), crate::DuplexBridgeOptions::default()).unwrap();
    bridge.abort(); let _ = bridge.wait().await;
    assert!(observer.wait_cleanup(Duration::from_secs(1)).await.complete);
    drop(peer); drop(remote); client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn native_tcp_duplex_passive_wait_cancellation_and_native_prefix_are_preserved() {
    use tokio::io::AsyncWriteExt;
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (native, peer) = tokio::join!(crate::NativeTcpDuplex::connect(&fixture.environment,
        listener.local_addr().unwrap(), crate::NativeTcpDuplexOptions::default()), listener.accept());
    let (remote, stream) = tokio::join!(client.open_stream("tcp", Metadata::empty(), 1), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let bridge = crate::DuplexBridge::with_native_tcp(stream, native.unwrap(), crate::DuplexBridgeOptions::default()).unwrap();
    bridge.start().unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(1), bridge.wait()).await.is_err());
    let mut peer = peer.unwrap().0;
    peer.write_all(b"tail").await.unwrap();
    let partial = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let progress = bridge.progress();
            if progress.b_to_a.destination_accepted_bytes == 1 && progress.b_to_a.source_read_bytes > 1 {
                // TCP may split the source into multiple reads. The bridge
                // retains exactly the prefix it consumed, not unread OS bytes.
                let read = progress.b_to_a.source_read_bytes as usize;
                assert!(read <= 4);
                assert_eq!(progress.b_to_a.unaccepted_tail, Bytes::copy_from_slice(&b"tail"[1..read]));
                break progress.b_to_a;
            }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    bridge.abort();
    let error = tokio::time::timeout(Duration::from_secs(5), bridge.wait()).await.unwrap().unwrap_err();
    assert_eq!(error.progress.b_to_a.source_read_bytes, partial.source_read_bytes);
    assert_eq!(error.progress.b_to_a.destination_accepted_bytes, 1);
    assert_eq!(error.progress.b_to_a.unaccepted_tail, partial.unaccepted_tail);
    assert_eq!(error.progress.first_error, None);
    drop(remote); client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn native_tcp_duplex_rejects_foreign_environment_without_claiming_raw_stream() {
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let foreign = crate::TransportEnvironment::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (native, peer) = tokio::join!(crate::NativeTcpDuplex::connect(&foreign,
        listener.local_addr().unwrap(), crate::NativeTcpDuplexOptions::default()), listener.accept());
    let native = native.unwrap();
    let observer = native.clone();
    let (remote, stream) = tokio::join!(client.open_stream("tcp", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let error = crate::DuplexBridge::with_native_tcp(stream.clone(), native, crate::DuplexBridgeOptions::default()).unwrap_err();
    assert_eq!(error.reason, crate::DuplexBridgeErrorReason::OwnerUnavailable);
    assert!(stream.read_owner().unwrap().acquire().is_ok());
    observer.close().unwrap();
    assert!(observer.wait_cleanup(Duration::from_secs(1)).await.complete);
    drop(peer); drop(remote); drop(stream);
    client.close(); server.close(); c_task.abort(); s_task.abort();
}

#[tokio::test]
async fn native_tcp_duplex_expired_unclaimed_owner_is_closed_before_bridge_io() {
    let (fixture, c, s) = record_pair_for_limits(Profile::X25519);
    let (client, server, c_task, s_task) = link(&fixture.environment, c, s);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (native, peer) = tokio::join!(crate::NativeTcpDuplex::connect(&fixture.environment,
        listener.local_addr().unwrap(), crate::NativeTcpDuplexOptions {
            prepared_timeout: Duration::from_millis(1), ..crate::NativeTcpDuplexOptions::default()
        }), listener.accept());
    let native = native.unwrap();
    assert!(native.wait_cleanup(Duration::from_secs(1)).await.complete);
    let (remote, stream) = tokio::join!(client.open_stream("tcp", Metadata::empty(), 65536), async {
        server.next_open().await.unwrap().accept(65536).unwrap()
    });
    let error = crate::DuplexBridge::with_native_tcp(stream.clone(), native, crate::DuplexBridgeOptions::default()).unwrap_err();
    assert_eq!(error.reason, crate::DuplexBridgeErrorReason::OwnerUnavailable);
    assert_eq!(error.progress.b_to_a.source_read_bytes, 0);
    assert!(stream.read_owner().is_some());
    drop(peer); drop(remote); drop(stream); client.close(); server.close(); c_task.abort(); s_task.abort();
}


#[tokio::test]
async fn native_tcp_duplex_environment_close_retires_socket_but_keeps_facade_charge() {
    let environment = crate::TransportEnvironment::new();
    let before = environment.resource_usage();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (native, peer) = tokio::join!(crate::NativeTcpDuplex::connect(&environment,
        listener.local_addr().unwrap(), crate::NativeTcpDuplexOptions::default()), listener.accept());
    let native = native.unwrap();
    let observer = native.clone();
    environment.root().close();
    assert!(native.wait_cleanup(Duration::from_secs(1)).await.complete);
    let retired = environment.resource_usage();
    assert_eq!(retired.native_handles, before.native_handles);
    assert_eq!(retired.connections, before.connections);
    assert_eq!(retired.tasks, before.tasks);
    assert_eq!(retired.timers, before.timers);
    assert_eq!(retired.provider_bytes, before.provider_bytes);
    assert_eq!(retired.sdk_bytes, before.sdk_bytes + 512);
    assert_eq!(retired.items, before.items + 1);
    drop(native);
    assert_eq!(environment.resource_usage(), retired);
    drop(observer);
    assert!(tokio::time::timeout(Duration::from_secs(1), environment.wait_cleanup()).await.unwrap().complete);
    assert_eq!(environment.resource_usage(), before);
    drop(peer);
}


#[tokio::test]
async fn native_tcp_duplex_dropped_connect_releases_private_preparation() {
    let environment = crate::TransportEnvironment::new();
    let before = environment.resource_usage();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut connecting = Box::pin(crate::NativeTcpDuplex::connect(&environment,
        listener.local_addr().unwrap(), crate::NativeTcpDuplexOptions::default()));
    let completed = std::future::poll_fn(|context| {
        std::task::Poll::Ready(match std::future::Future::poll(connecting.as_mut(), context) {
            std::task::Poll::Ready(endpoint) => Some(endpoint),
            std::task::Poll::Pending => None,
        })
    }).await;
    drop(connecting);
    // Fast local connection completion is legal too. Drop that complete
    // private owner so either scheduling outcome has the same obligations.
    drop(completed);
    tokio::time::timeout(Duration::from_secs(1), async {
        while environment.resource_usage() != before { tokio::task::yield_now().await; }
    }).await.unwrap();
    environment.root().close();
    assert!(environment.cleanup_status().complete);
}
