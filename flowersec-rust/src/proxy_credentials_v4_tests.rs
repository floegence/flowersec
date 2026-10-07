mod credential_lifecycle {
    use super::*;
    use crate::{
        ApplicationBinding, ProxyCredentialAuthorizer, ProxyCredentialError, ProxyCredentialMode,
        ProxyCredentialPolicy, ProxyCredentialScope, ProxyServerInvalidation, TransportEnvironment,
        TransportEnvironmentOptions,
    };

    const ORIGIN: &str = "https://app.example";
    const SURFACE: [u8; 16] = [9; 16];

    struct ReleaseCheckpoint(Arc<(Mutex<bool>, std::sync::Condvar)>);
    impl Drop for ReleaseCheckpoint {
        fn drop(&mut self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_all();
        }
    }
    fn checkpoint(
        runtime: &crate::proxy_credentials_v4::CredentialRuntime,
        stage: &'static str,
    ) -> (std::sync::mpsc::Receiver<()>, ReleaseCheckpoint) {
        let (entered, waiting) = std::sync::mpsc::channel();
        let barrier = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let blocked = barrier.clone();
        runtime.set_lifecycle_hook(Arc::new(move |current| {
            if current != stage {
                return;
            }
            entered.send(()).unwrap();
            let guard = blocked.0.lock().unwrap();
            let (released, timeout) = blocked
                .1
                .wait_timeout_while(guard, Duration::from_secs(5), |released| !*released)
                .unwrap();
            assert!(
                *released && !timeout.timed_out(),
                "credential checkpoint was not released"
            );
        }));
        (waiting, ReleaseCheckpoint(barrier))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_cannot_pass_request_capture_or_last_backing_release() {
        for stage in ["after_admission_unlock", "before_backing_release"] {
            let (environment, server) = server(ProxyCredentialMode::UpstreamCookieSession, 1);
            let original = server
                .bind_upstream_credentials(authentication(), SURFACE, ORIGIN)
                .await
                .unwrap();
            let association = original.attachment().unwrap();
            let runtime = server.inner.credentials.as_ref().unwrap().clone();
            let uncharged = environment.resource_usage();
            let (entered, release) = checkpoint(&runtime, stage);
            let request = if stage == "before_backing_release" {
                Some(
                    runtime
                        .request(
                            Some(authentication()),
                            &association,
                            "include",
                            ORIGIN,
                            "/",
                            &[],
                            false,
                        )
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            let worker = runtime.clone();
            let handle = tokio::runtime::Handle::current();
            let thread = std::thread::spawn(move || {
                if let Some(request) = request {
                    drop(request);
                    None
                } else {
                    Some(
                        handle
                            .block_on(worker.request(
                                Some(authentication()),
                                &association,
                                "include",
                                ORIGIN,
                                "/",
                                &[],
                                false,
                            ))
                            .unwrap(),
                    )
                }
            });
            entered.recv_timeout(Duration::from_secs(3)).unwrap();
            original.close();
            let cleanup = original.cleanup_status();
            assert!(!cleanup.complete, "cleanup escaped {stage}");
            assert_eq!(cleanup.pending_callbacks, 1);
            assert_eq!(
                original.attachment(),
                Err(ProxyCredentialError::ScopeUnavailable)
            );
            let charged = environment.resource_usage();
            assert!(
                charged.sdk_bytes > uncharged.sdk_bytes,
                "request backing disappeared before {stage}"
            );
            let cancellation = CancellationToken::new();
            let mut waiting = Box::pin(original.wait_cleanup(&cancellation));
            assert!(matches!(
                futures_util::poll!(waiting.as_mut()),
                std::task::Poll::Pending
            ));
            drop(release);
            let request = thread.join().unwrap();
            if let Some(request) = request {
                assert_eq!(request.check(), Err(ProxyCredentialError::ScopeUnavailable));
                assert!(!original.cleanup_status().complete);
                drop(request);
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(1), waiting)
                    .await
                    .unwrap()
                    .unwrap()
                    .complete
            );
            assert_eq!(environment.resource_usage(), uncharged);
            drop(original);
            server.close().await;
            drop((runtime, server));
            assert!(environment.close().await.unwrap().complete);
        }
    }

    fn authentication() -> ApplicationBinding {
        ApplicationBinding {
            artifact: [1; 32],
            client_identity: [2; 32],
            server_identity: [3; 32],
            route: [4; 32],
            attempt: [5; 16],
            candidate: [6; 16],
        }
    }

    #[derive(Debug)]
    struct Authorizer;
    #[async_trait]
    impl ProxyCredentialAuthorizer for Authorizer {
        async fn resolve_scope(
            &self,
            binding: ApplicationBinding,
            surface: [u8; 16],
        ) -> Result<ProxyCredentialScope, ProxyCredentialError> {
            if binding != authentication() {
                return Err(ProxyCredentialError::ScopeUnavailable);
            }
            Ok(ProxyCredentialScope {
                tenant: "tenant".into(),
                principal: "principal".into(),
                policy_revision: "policy-v1".into(),
                surface_owner: surface,
                content_origin: ORIGIN.parse().unwrap(),
                scope_not_after_ms: 60_000,
                idle_timeout: Duration::from_secs(30),
                delegated_first_party: true,
            })
        }
        async fn authorize(
            &self,
            binding: ApplicationBinding,
            scope: &ProxyCredentialScope,
        ) -> Result<(), ProxyCredentialError> {
            if binding != authentication() || scope.principal != "principal" {
                return Err(ProxyCredentialError::ScopeUnavailable);
            }
            Ok(())
        }
        async fn external_headers(
            &self,
            binding: ApplicationBinding,
            _: &Url,
        ) -> Result<Vec<(String, String)>, ProxyCredentialError> {
            if binding != authentication() {
                return Err(ProxyCredentialError::ScopeUnavailable);
            }
            Ok(vec![(
                "authorization".into(),
                "Bearer trusted-upstream".into(),
            )])
        }
    }

    fn server(
        mode: ProxyCredentialMode,
        max_owners: usize,
    ) -> (Arc<TransportEnvironment>, ProxyServer) {
        let environment = Arc::new(
            TransportEnvironment::with_options(TransportEnvironmentOptions {
                clock: Some(crate::environment_v4::tests::TestClock::new(1000, 1010)),
                ..TransportEnvironmentOptions::default()
            })
            .unwrap(),
        );
        let mut options = test_options("http://127.0.0.1:8080".parse().unwrap());
        options.credentials = Some(ProxyCredentialPolicy {
            mode,
            environment: environment.clone(),
            authorizer: Arc::new(Authorizer),
            allow_websocket: false,
            max_owners,
            max_total_cookie_bytes: 65536,
        });
        (environment, ProxyServer::new(options).unwrap())
    }

    #[tokio::test]
    async fn clear_invalidates_original_cookie_authority_before_held_request_cleanup() {
        let (environment, server) = server(ProxyCredentialMode::UpstreamCookieSession, 2);
        let baseline = environment.resource_usage();
        let original = server
            .bind_upstream_credentials(authentication(), SURFACE, ORIGIN)
            .await
            .unwrap();
        let association = original.attachment().unwrap();
        assert!(!format!("{original:?}").contains(&association));
        let runtime = server.inner.credentials.as_ref().unwrap();
        let request = runtime
            .request(
                Some(authentication()),
                &association,
                "include",
                ORIGIN,
                "/account/login",
                &[],
                false,
            )
            .await
            .unwrap();
        assert!(request.managed());
        let mut headers = HeaderMap::new();
        for cookie in [
            "root=one; Path=/; HttpOnly",
            "account=two; Path=/account",
            "implicit=three",
            "secure=secret; Secure",
            "foreign=secret; Domain=other.example",
            "partition=secret; Partitioned",
            "__Host-forged=secret; Path=/",
            "cross=secret; SameSite=None",
        ] {
            headers.append(header::SET_COOKIE, cookie.parse().unwrap());
        }
        request.receive_cookies(&headers, "/account/login").unwrap();
        drop(request);
        let held = runtime
            .request(
                Some(authentication()),
                &association,
                "include",
                ORIGIN,
                "/account/profile",
                &[],
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            held.headers,
            vec![(
                "cookie".into(),
                "account=two; implicit=three; root=one".into()
            )]
        );
        let outside = runtime
            .request(
                Some(authentication()),
                &association,
                "include",
                ORIGIN,
                "/accounting",
                &[],
                false,
            )
            .await
            .unwrap();
        assert_eq!(outside.headers, vec![("cookie".into(), "root=one".into())]);
        drop(outside);
        for (mode, origin) in [("omit", ORIGIN), ("same-origin", "https://other.example")] {
            let omitted = runtime
                .request(
                    Some(authentication()),
                    &association,
                    mode,
                    origin,
                    "/account",
                    &[],
                    false,
                )
                .await
                .unwrap();
            assert!(omitted.headers.is_empty());
            drop(omitted);
        }
        let mut foreign = authentication();
        foreign.client_identity = [8; 32];
        assert_eq!(
            runtime
                .request(
                    Some(foreign),
                    &association,
                    "include",
                    ORIGIN,
                    "/",
                    &[],
                    false
                )
                .await
                .unwrap_err(),
            ProxyCredentialError::ScopeUnavailable
        );
        assert_eq!(
            runtime
                .request(
                    Some(authentication()),
                    &association,
                    "include",
                    ORIGIN,
                    "/",
                    &[],
                    true
                )
                .await
                .unwrap_err(),
            ProxyCredentialError::ScopeUnavailable
        );
        let cleared = server
            .clear_upstream_credentials(authentication(), SURFACE, &original)
            .await
            .unwrap();
        assert_eq!(
            cleared.server_invalidation,
            ProxyServerInvalidation::Confirmed
        );
        assert!(cleared.error.is_none());
        assert!(!cleared.cleanup.complete);
        assert_eq!(cleared.cleanup.pending_callbacks, 1);
        assert!(held.cancellation().is_cancelled());
        assert_eq!(held.check(), Err(ProxyCredentialError::ScopeUnavailable));
        assert_eq!(
            held.receive_cookies(&headers, "/"),
            Err(ProxyCredentialError::ScopeUnavailable)
        );
        assert_eq!(
            original.attachment(),
            Err(ProxyCredentialError::ScopeUnavailable)
        );
        let replacement = cleared.replacement.unwrap();
        let replacement_attachment = replacement.attachment().unwrap();
        assert_ne!(replacement_attachment, association);
        let empty = runtime
            .request(
                Some(authentication()),
                &replacement_attachment,
                "include",
                ORIGIN,
                "/account",
                &[],
                false,
            )
            .await
            .unwrap();
        assert!(empty.headers.is_empty());
        drop(empty);
        let canceled = CancellationToken::new();
        canceled.cancel();
        assert_eq!(
            original.wait_cleanup(&canceled).await.unwrap_err(),
            ProxyCredentialError::ScopeUnavailable
        );
        drop(held);
        assert!(
            original
                .wait_cleanup(&CancellationToken::new())
                .await
                .unwrap()
                .complete
        );
        replacement.close();
        assert!(
            replacement
                .wait_cleanup(&CancellationToken::new())
                .await
                .unwrap()
                .complete
        );
        drop((original, replacement));
        server.close().await;
        assert_eq!(environment.resource_usage(), baseline);
        drop(server);
        assert!(environment.close().await.unwrap().complete);
    }

    #[tokio::test]
    async fn bounded_control_replay_preserves_clear_fact_when_replacement_cannot_fit() {
        let (environment, server) = server(ProxyCredentialMode::UpstreamCookieSession, 1);
        let runtime = server.inner.credentials.as_ref().unwrap();
        let bound = runtime
            .control(authentication(), SURFACE, "bind-1", 1, "", ORIGIN)
            .await
            .unwrap();
        let association = bound.context.unwrap();
        let replay = runtime
            .control(authentication(), SURFACE, "bind-1", 1, "", ORIGIN)
            .await
            .unwrap();
        assert_eq!(replay.context.as_deref(), Some(association.as_str()));
        assert_eq!(
            runtime
                .control(authentication(), SURFACE, "bind-2", 1, "", ORIGIN)
                .await
                .unwrap_err(),
            ProxyCredentialError::OperationConflict
        );
        assert_eq!(
            runtime
                .control(authentication(), SURFACE, "bind-1", 2, &association, "")
                .await
                .unwrap_err(),
            ProxyCredentialError::OperationConflict
        );
        let held = runtime
            .request(
                Some(authentication()),
                &association,
                "include",
                ORIGIN,
                "/",
                &[],
                false,
            )
            .await
            .unwrap();
        let cleared = runtime
            .control(authentication(), SURFACE, "clear-1", 2, &association, "")
            .await
            .unwrap();
        assert!(cleared.invalidated);
        assert!(cleared.context.is_none());
        assert_eq!(cleared.error, Some(ProxyCredentialError::UpdateFailed));
        let replay = runtime
            .control(authentication(), SURFACE, "clear-1", 2, &association, "")
            .await
            .unwrap();
        assert!(replay.invalidated);
        assert_eq!(replay.error, cleared.error);
        assert!(held.cancellation().is_cancelled());
        assert_eq!(
            runtime
                .request(
                    Some(authentication()),
                    &association,
                    "include",
                    ORIGIN,
                    "/",
                    &[],
                    false
                )
                .await
                .unwrap_err(),
            ProxyCredentialError::ScopeUnavailable
        );
        drop(held);
        let fresh = runtime
            .control(authentication(), SURFACE, "bind-3", 1, "", ORIGIN)
            .await
            .unwrap();
        let fresh = fresh.context.unwrap();
        assert_ne!(fresh, association);
        let disposed = runtime
            .control(authentication(), SURFACE, "dispose-1", 3, &fresh, "")
            .await
            .unwrap();
        assert!(disposed.invalidated && disposed.context.is_none() && disposed.error.is_none());
        server.close().await;
        drop(server);
        assert!(environment.close().await.unwrap().complete);
    }

    #[tokio::test]
    async fn external_credentials_require_trusted_authentication_and_reject_content_injection() {
        let (environment, server) = server(ProxyCredentialMode::External, 1);
        assert_eq!(
            server
                .bind_upstream_credentials(authentication(), SURFACE, ORIGIN)
                .await
                .unwrap_err(),
            ProxyCredentialError::ScopeUnavailable
        );
        let runtime = server.inner.credentials.as_ref().unwrap();
        for supplied in [
            vec![("Cookie".into(), "injected=value".into())],
            vec![("Authorization".into(), "Bearer injected".into())],
        ] {
            assert_eq!(
                runtime
                    .request(
                        Some(authentication()),
                        "",
                        "include",
                        ORIGIN,
                        "/",
                        &supplied,
                        false
                    )
                    .await
                    .unwrap_err(),
                ProxyCredentialError::ScopeUnavailable
            );
        }
        assert_eq!(
            runtime
                .request(None, "", "include", ORIGIN, "/", &[], false)
                .await
                .unwrap_err(),
            ProxyCredentialError::ScopeUnavailable
        );
        assert_eq!(
            runtime
                .request(
                    Some(authentication()),
                    "content-selected-context",
                    "include",
                    ORIGIN,
                    "/",
                    &[],
                    false
                )
                .await
                .unwrap_err(),
            ProxyCredentialError::ScopeUnavailable
        );
        let request = runtime
            .request(
                Some(authentication()),
                "",
                "include",
                ORIGIN,
                "/",
                &[],
                false,
            )
            .await
            .unwrap();
        assert!(!request.managed());
        assert_eq!(
            request.headers,
            vec![("authorization".into(), "Bearer trusted-upstream".into())]
        );
        request.receive_cookies(&HeaderMap::new(), "/").unwrap();
        server.close().await;
        assert_eq!(request.check(), Err(ProxyCredentialError::ScopeUnavailable));
        drop((request, server));
        assert!(environment.close().await.unwrap().complete);
    }
}
