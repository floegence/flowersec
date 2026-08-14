use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use flowersec::{
    Artifact, ArtifactLease, AuthorizationRecord, ConnectorOptions, ControlPlaneError, EndpointSet,
    Issuer, RuntimeAuthorizationRequest, SessionOptions, StreamMetadata,
    TunnelAuthorizationResponse, TunnelAuthorizer, TunnelIssueOptions, TunnelRuntime,
    TunnelRuntimeOptions, connect,
};
use tokio_util::sync::CancellationToken;

const TEST_CERT_DER_B64: &str = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==";
const TEST_KEY_DER_B64: &str = "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6";

struct Records {
    records: Mutex<HashMap<String, AuthorizationRecord>>,
    remote_addresses: Mutex<Vec<String>>,
    next_lease: AtomicUsize,
    releases: AtomicUsize,
}

#[async_trait]
impl TunnelAuthorizer for Records {
    async fn authorize(
        &self,
        request: RuntimeAuthorizationRequest,
    ) -> Result<TunnelAuthorizationResponse, ControlPlaneError> {
        self.remote_addresses
            .lock()
            .unwrap()
            .push(request.remote_address().to_owned());
        let record = self
            .records
            .lock()
            .unwrap()
            .get(request.lookup_key())
            .cloned()
            .ok_or(ControlPlaneError::InvalidInput)?;
        let lease = format!("lease-{}", self.next_lease.fetch_add(1, Ordering::SeqCst));
        request.authorize_tunnel(&record, &lease)
    }

    async fn release(&self, _lease_id: &str) {
        self.releases.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_wss_tunnel_relays_one_end_to_end_session_without_terminating_it() {
    let authorizer = Arc::new(Records {
        records: Mutex::new(HashMap::new()),
        remote_addresses: Mutex::new(Vec::new()),
        next_lease: AtomicUsize::new(1),
        releases: AtomicUsize::new(0),
    });
    let cert = STANDARD.decode(TEST_CERT_DER_B64).unwrap();
    let key = STANDARD.decode(TEST_KEY_DER_B64).unwrap();
    let runtime = Arc::new(
        TunnelRuntime::bind_websocket(
            TunnelRuntimeOptions {
                bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                certificate_chain_der: vec![cert.clone()],
                private_key_der: key,
                allowed_origins: vec!["https://native-endpoint.test".into()],
                max_inbound_streams: 8,
                pair_timeout: Duration::from_secs(5),
                max_pending_legs: 8,
                max_active_pairs: 4,
            },
            authorizer.clone(),
        )
        .expect("bind WSS tunnel runtime"),
    );
    let address = runtime.local_address().unwrap();
    let mut session = SessionOptions::new("rust-wss-tunnel");
    session.max_inbound_streams = 8;
    let pair = Issuer::new()
        .issue_tunnel_pair(TunnelIssueOptions {
            session,
            endpoints: EndpointSet::new([format!("wss://localhost:{}/", address.port())]).unwrap(),
            rendezvous_group_id: "rust-wss-tunnel-group".into(),
            listener_audience: "rust-wss-tunnel-listener".into(),
            first_endpoint_id: "endpoint-a".into(),
            second_endpoint_id: "endpoint-b".into(),
            allow_replacement: false,
        })
        .expect("issue tunnel pair");
    {
        let mut records = authorizer.records.lock().unwrap();
        records.insert(
            pair.first().lookup_key().to_owned(),
            pair.first().authorization_record(),
        );
        records.insert(
            pair.second().lookup_key().to_owned(),
            pair.second().authorization_record(),
        );
    }
    let runtime_cancel = CancellationToken::new();
    let runtime_task = tokio::spawn({
        let runtime = runtime.clone();
        let cancellation = runtime_cancel.clone();
        async move { runtime.serve(cancellation).await }
    });

    let options = || {
        ConnectorOptions::new()
            .with_trust_roots_der(vec![cert.clone()])
            .unwrap()
            .with_websocket_origin("https://native-endpoint.test")
            .unwrap()
            .with_connect_timeout(Duration::from_secs(5))
            .unwrap()
    };
    let first = ArtifactLease::new(
        Artifact::parse(pair.first().artifact_json()).unwrap(),
        || async { Ok(()) },
    );
    let second = ArtifactLease::new(
        Artifact::parse(pair.second().artifact_json()).unwrap(),
        || async { Ok(()) },
    );
    let (first, second) = tokio::join!(connect(first, options()), connect(second, options()));
    let first = first.expect("connect first endpoint");
    let second = second.expect("connect second endpoint");

    let receiver = tokio::spawn({
        let second = second.clone();
        async move {
            let incoming = second.accept_stream().await.expect("accept relayed stream");
            assert_eq!(incoming.kind(), "tunnel.opaque");
            assert_eq!(
                incoming.stream().read().await.unwrap(),
                Some(Bytes::from_static(b"encrypted endpoint payload"))
            );
            assert_eq!(incoming.stream().read().await.unwrap(), None);
            incoming
                .stream()
                .write(Bytes::from_static(b"reply"))
                .await
                .unwrap();
            incoming.stream().close_write().await.unwrap();
        }
    });
    let stream = first
        .open_stream("tunnel.opaque", StreamMetadata::empty())
        .await
        .expect("open relayed stream");
    stream
        .write(Bytes::from_static(b"encrypted endpoint payload"))
        .await
        .unwrap();
    stream.close_write().await.unwrap();
    assert_eq!(
        stream.read().await.unwrap(),
        Some(Bytes::from_static(b"reply"))
    );
    assert_eq!(stream.read().await.unwrap(), None);
    receiver.await.unwrap();

    let close_result = tokio::time::timeout(Duration::from_secs(1), runtime.close()).await;
    let releases_when_close_returned = authorizer.releases.load(Ordering::SeqCst);
    let _ = tokio::join!(first.close(), second.close());
    runtime_cancel.cancel();
    runtime_task.await.unwrap().unwrap();
    assert!(close_result.is_ok(), "TunnelRuntime.close must be bounded");
    assert_eq!(
        releases_when_close_returned, 2,
        "TunnelRuntime.close must wait for active pair lease cleanup"
    );
    let remote_addresses = authorizer.remote_addresses.lock().unwrap().clone();
    assert_eq!(remote_addresses.len(), 2);
    assert!(
        remote_addresses
            .iter()
            .all(|address| address.starts_with("127.0.0.1:"))
    );
    assert!(
        remote_addresses
            .iter()
            .all(|address| address != "websocket")
    );
    std::net::TcpListener::bind(address)
        .expect("TunnelRuntime.close must release the listener socket before returning");
}
