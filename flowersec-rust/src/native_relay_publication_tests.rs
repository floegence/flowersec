use super::provider_regression_tests::{
    accepted_wss_pair, limits, read_wss_wire, test_root, wait_provider_cleanup, wire,
};
use super::*;

#[tokio::test]
async fn shared_wss_mapping_and_maintenance_join_original_publication() {
    let root = test_root();
    let accounts = [
        root.admit([0x61; 32], crate::environment_v4::tests::bounds())
            .unwrap(),
        root.admit([0x62; 32], crate::environment_v4::tests::bounds())
            .unwrap(),
    ];
    let baseline = root.charged();
    let limits = limits();
    let (provider, incoming, client, mut client_incoming, accepted, budget) =
        accepted_wss_pair(root.clone(), &accounts[0], limits)
            .await
            .unwrap();
    let other_budget = wss::test_relay_budget(accounts[1].clone(), limits).unwrap();
    let policies = [
        wss::Policy::test_policy(
            limits,
            1,
            "example.com".into(),
            1,
            Vec::new(),
            None,
            budget.clone(),
        )
        .unwrap(),
        wss::Policy::test_policy(
            limits,
            0,
            "example.com".into(),
            1,
            Vec::new(),
            None,
            other_budget.clone(),
        )
        .unwrap(),
    ];
    let pair = Pair::new(
        &accounts,
        [limits; 2],
        &policies,
        Duration::from_secs(3),
        [4; 2],
    )
    .unwrap()
    .unwrap();
    let charged = root.charged();
    let before_bytes = budget.test_reserved_bytes();
    let mapping_wire = wire(8, 0x71, 1);
    let maintenance_wire = wire(6, 0, 1);
    let mapping_cancel = CancellationToken::new();
    {
        // Poll the mapping publisher once to submit its actual WSS write, then
        // leave its continuation pending even after the peer receives it.
        // Maintenance must join that original publication before using the
        // provider's single send position.
        let mapping = pair.publish_shared(0, &provider, &mapping_wire, &mapping_cancel);
        tokio::pin!(mapping);
        assert!(futures_util::poll!(mapping.as_mut()).is_pending());
        assert_eq!(read_wss_wire(&mut client_incoming).await, mapping_wire);

        let providers = [provider.clone(), client.clone()];
        let connections = [None, None];
        let maintenance = pair.lane(
            PendingWire {
                role: 1,
                wire: maintenance_wire.clone(),
                mapping: None,
                open: false,
                buffer_wake: pair.buffers.wake(1),
            },
            &providers,
            &connections,
        );
        tokio::pin!(maintenance);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), maintenance.as_mut())
                .await
                .is_err(),
            "maintenance completed before the original mapping publication returned"
        );
        assert_eq!(budget.test_reserved_bytes(), before_bytes + 44);
        assert!(client_incoming.try_recv().is_err());
        assert_eq!(root.charged(), charged);

        mapping.await.unwrap();
        assert!(matches!(maintenance.await.unwrap(), LaneOutcome::Done));
        assert_eq!(read_wss_wire(&mut client_incoming).await, maintenance_wire);
    }
    assert_eq!(budget.test_reserved_bytes(), before_bytes + 88);
    assert_eq!(root.charged(), charged);

    pair.wait_cleanup().await;
    drop(pair);
    drop(policies);
    drop(incoming);
    drop(client_incoming);
    wait_provider_cleanup(&provider).await;
    wait_provider_cleanup(&client).await;
    drop(accepted);
    drop(provider);
    drop(client);
    drop(budget);
    drop(other_budget);
    assert_eq!(root.charged(), baseline);
}
