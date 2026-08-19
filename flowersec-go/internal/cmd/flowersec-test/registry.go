package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func registry() []registeredTest {
	tests := []registeredTest{
		commandEntry("controller/go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestConnectionControllerSharedLifecycleVectors$", "."),
		commandEntry("controller/go-real-network-restart", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestConnectionControllerRealNetworkRestartReconnect$", "."),
		commandEntry("controller/go-websocket-handlers", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestConnectionControllerWebSocketHandlersSurviveTwoGenerations$", "."),
		vitestEntry("controller/typescript", "acceptance", "src/v3/controllerVectors.test.ts", ""),
		vitestEntry("compat/v2/controller/typescript", "acceptance", "src/connectionController.vectors.test.ts", ""),
		vitestEntry("compat/v2/controller/typescript-real-network-restart", "acceptance", "src/node/connectionController.integration.test.ts", "restarts a WSS peer with a fresh lease and does not replay old operations"),
		commandEntry("controller/rust", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connection_controller::"),
		commandEntry("compat/v2/controller/rust-raw-quic", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connection_controller_replaces_terminated_raw_quic_session_without_replay"),
		commandEntry("compat/v2/controller/rust-websocket-handlers", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--test", "connection_controller_websocket"),
		commandEntry("protocol/go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "./internal/protocolv3", "./internal/artifactv3", "./internal/admissionv3", "./internal/sessionv3", "./internal/runtimev3", "./internal/idna15", "./internal/rpc", "."),
		commandEntry("compat/v2/protocol/go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "./internal/protocolv2", "./internal/artifactv2", "./internal/admissionv2", "./internal/session"),
		commandEntry("protocol/typescript", "acceptance", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "test", "--", "--run", "src/v3"),
		commandEntry("compat/v2/protocol/typescript", "acceptance", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "test", "--", "--run", "src/v2"),
		commandEntry("protocol/rust", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "v3"),
		commandEntry("compat/v2/protocol/rust", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "v2"),
		commandEntry("server/go-acceptor", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestAcceptor", "."),
		commandEntry("server/go-rpc-notification", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^Test(SessionHandlersNotificationRegistrationIsBoundedAndFrozen|PublicRPCPeerAndSessionHandlersExposeNotifications)$", "."),
		commandEntry("server/go-controlplane", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "./controlplane"),
		vitestEntry("compat/v2/server/typescript-controlplane", "acceptance", "src/node/controlplane.test.ts", "Node control-plane public contract"),
		commandEntry("compat/v2/server/rust-controlplane", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--test", "controlplane"),
		commandEntry("server/go-proxy", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProxyServer", "."),
		vitestEntry("server/typescript-acceptor", "acceptance", "src/node/serverRuntimeV3.integration.test.ts", "accepts a production v3 WSS direct session through FSB3 and FSH3"),
		vitestEntry("controller/typescript-rpc-handlers-v3", "acceptance", "src/node/serverRuntimeV3.integration.test.ts", "reuses frozen client RPC handlers with a fresh router across v3 controller generations"),
		vitestEntry("compat/v2/server/typescript-acceptor", "acceptance", "src/node/acceptor.integration.test.ts", "freezes handlers before establishing a direct WebSocket Session"),
		vitestEntry("compat/v2/server/typescript-rpc-notification", "acceptance", "src/node/acceptor.test.ts", "keeps notification registrations isolated from request handlers and freezes them"),
		vitestEntry("compat/v2/server/typescript-proxy", "acceptance", "src/node/proxyServer.integration.test.ts", "Node ProxyServer real Session integration"),
		commandEntry("compat/v2/server/rust-proxy", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--test", "proxy_server_public"),
		vitestEntry("compat/v2/interop/browser-proxy/server-matrix", "acceptance", "src/interop/proxyServerMatrix.integration.test.ts", "Browser TypeScript ProxyServer interoperability"),
		commandEntry("compat/v2/server/rust-acceptor", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "public_acceptor_establishes_opaque_direct_session"),
		commandEntry("compat/v2/server/rust-acceptor-handlers", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "public_acceptor_freezes_rpc_and_stream_handlers_before_establishment"),
		commandEntry("server/rust-acceptor", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connector_v3::tests::production_websocket_connector_completes_ca_admission_and_session", "--", "--exact"),
		commandEntry("server/rust-acceptor-handlers", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connector_v3::tests::production_websocket_acceptor_binds_handlers_before_session_establishment", "--", "--exact"),
		commandEntry("carrier/go-direct", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProductDirectCarriersUsePublicConnectorAndAdmission$", "./internal/transporttest"),
		commandEntry("compat/v2/carrier/go-loopback-plaintext-direct", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^(TestAcceptorEstablishesPlaintextLoopbackDirectSession|TestValidateReadyAllowsPlaintextOnlyForLoopbackDirect)$", ".", "./internal/carrier/websocket"),
		vitestEntry("compat/v2/carrier/typescript-loopback-plaintext-direct", "acceptance", "src/node/connectSession.integration.test.ts", "establishes a complete direct session over plaintext loopback"),
		commandEntry("compat/v2/carrier/rust-loopback-plaintext-direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--test", "websocket_direct", "secure_or_mixed_candidates_without_roots_fail_before_spend"),
		commandEntry("compat/v2/carrier/rust-websocket-direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--test", "websocket_direct"),
		commandEntry("compat/v2/carrier/rust-websocket-tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--test", "websocket_tunnel"),
		commandEntry("carrier/rust-websocket-direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connector_v3::tests::production_websocket_connector_completes_ca_admission_and_session", "--", "--exact"),
		commandEntry("carrier/rust-websocket-tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connector_v3::tests::production_wss_tunnel_runtime_relays_a_complete_v3_session", "--", "--exact"),
		commandEntry("carrier/rust-raw-quic-tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "raw_quic_v3_integration_tests::production_raw_quic_tunnel_runtime_relays_a_complete_v3_session", "--", "--exact"),
		vitestEntry("carrier/typescript-websocket-tunnel", "acceptance", "src/node/serverRuntimeV3.integration.test.ts", "pairs production v3 WSS tunnel roles without exposing the encrypted session"),
		commandEntry("server/typescript-raw-quic-direct", "acceptance", 10*time.Minute, "node", "scripts/server-parity-native-addon.mjs", "--test-title", "connects and accepts direct raw QUIC through FSB3 and FSH3"),
		commandEntry("server/typescript-raw-quic-tunnel", "acceptance", 10*time.Minute, "node", "scripts/server-parity-native-addon.mjs", "--test-title", "pairs raw QUIC tunnel roles through production v3 listeners"),
		vitestEntry("compat/v2/carrier/typescript-websocket-tunnel", "acceptance", "src/node/tunnelRuntime.websocket.integration.test.ts", "Node TunnelRuntime relays opaque WSS streams and cleans up paired and timed-out leases"),
		commandEntry("carrier/go-tunnel", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProductionTunnelTopologiesRunColdRPCBulkAndCleanup$", "./internal/transporttest/tunnelworkload"),
		commandEntry("carrier/go-webtransport-tunnel", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestBrowserTunnelTopologiesUseProductionWebTransportBrokerPath$", "./internal/transporttest/tunnelworkload"),
		commandEntry("compat/v2/carrier/go-tunnel", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProductionTunnelCarrierCartesianMatrixCarriesEncryptedSessions$", "./internal/tunnelv2"),
		vitestEntry("interop/typescript-go/wss/direct", "acceptance", "src/interop/goSessionV3.integration.test.ts", "runs direct FSB3/FSH3 and Session semantics over Go WSS"),
		vitestEntry("interop/typescript-go/wss/tunnel", "acceptance", "src/interop/goSessionV3.integration.test.ts", "runs tunnel-role FSB3/FSH3 and Session semantics over Go WSS"),
		vitestEntry("compat/v2/interop/typescript-go/wss/direct", "acceptance", "src/interop/goSession.integration.test.ts", "runs direct admission and Session semantics over WSS"),
		vitestEntry("compat/v2/interop/typescript-go/wss/tunnel", "acceptance", "src/interop/goSession.integration.test.ts", "runs tunnel admission and Session semantics over WSS"),
		commandEntry("interop/rust-go/raw-quic/direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "raw_quic_v3_integration_tests::go_and_rust_run_full_v3_sessions_in_both_directions_for_direct_and_tunnel", "--", "--exact"),
		commandEntry("interop/rust-go/raw-quic/tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "raw_quic_v3_integration_tests::go_and_rust_run_full_v3_sessions_in_both_directions_for_direct_and_tunnel", "--", "--exact"),
		commandEntry("interop/go-rust/raw-quic/direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "raw_quic_v3_integration_tests::go_and_rust_run_full_v3_sessions_in_both_directions_for_direct_and_tunnel", "--", "--exact"),
		commandEntry("interop/go-rust/raw-quic/tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "raw_quic_v3_integration_tests::go_and_rust_run_full_v3_sessions_in_both_directions_for_direct_and_tunnel", "--", "--exact"),
		commandEntry("compat/v2/interop/rust-go/raw-quic/direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "rust_and_go_run_full_session_v2_over_raw_quic_direct", "--", "--exact"),
		commandEntry("compat/v2/interop/rust-go/raw-quic/tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "rust_and_go_run_full_session_v2_over_raw_quic_tunnel", "--", "--exact"),
		commandEntry("compat/v2/interop/go-rust/raw-quic/direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "raw_quic_v2_integration_tests::go_client_to_rust_server_runs_admission_over_native_quic_direct", "--", "--exact"),
		commandEntry("compat/v2/interop/go-rust/raw-quic/tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "raw_quic_v2_integration_tests::go_client_to_rust_server_runs_admission_over_native_quic_tunnel", "--", "--exact"),
		commandEntry("carrier/rust-tls13-handshake", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "tls_v3::tests::configs_are_tls13_only_without_early_data_or_resumption", "--", "--exact"),
		commandEntry("carrier/rust-tls-rejection", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "tls_v3::tests"),
		commandEntry("carrier/node-native-addon/lifecycle", "acceptance", 10*time.Minute, "make", "native-addon-test"),
		browserSmokeEntry("browser/chromium/webtransport/direct", "Chromium runs production v3 WebTransport with the artifact TLS pin"),
		browserSmokeEntry("browser/chromium/webtransport/pin-rejection", "Chromium WebTransport rejects an unknown v3 pin before durable spend"),
		browserSmokeEntry("browser/chromium/webtransport/hash-constructor-unsupported", "Chromium WebTransport fails closed when certificate hashes are unsupported"),
		browserSmokeEntry("browser/chromium/webtransport/ca-policy", "Chromium WebTransport delegates CA trust without certificate hashes"),
		browserSmokeEntry("browser/chromium/webtransport/public-ca", "Chromium WebTransport production adapter accepts a public-CA certificate in CA mode"),
		browserSmokeEntry("browser/chromium/webtransport/public-ca-wrong-pin-no-fallback", "Chromium WebTransport production adapter rejects a wrong pin for a public-CA certificate without CA fallback"),
		browserSmokeEntry("browser/chromium/websocket/self-contained", "Portable browsers run the v3 WebSocket client contract"),
		browserSmokeEntry("compat/v2/browser/chromium/webtransport/peer-termination", "Chromium WebTransport closes bounded concurrent streams after peer termination"),
		browserSmokeEntry("compat/v2/browser/chromium/websocket/self-contained", "Portable browsers run the explicit v2 compatibility WebSocket client contract"),
		browserSmokeEntry("compat/v2/browser/chromium/proxy-service-worker", "Chromium runs the Service Worker proxy product chain"),
		browserClientProfileEntry("compat/v2/browser/chromium/websocket/go/direct", "go/direct"),
		browserClientProfileEntry("compat/v2/browser/chromium/websocket/node/direct", "node/direct"),
		browserClientProfileEntry("compat/v2/browser/chromium/websocket/via-go-to-rust/tunnel", "via-go-to-rust/tunnel"),
		browserSmokeEntry("compat/v2/browser/chromium-tunnel-wt-wss", "Chromium WebTransport tunnel bridges to production Go wss"),
		browserSmokeEntry("compat/v2/browser/chromium-tunnel-wt-quic", "Chromium WebTransport tunnel bridges to production Go raw_quic"),
		browserCompatibilityEntry("compat/v2/browser/firefox/webtransport-capability", "firefox", "Firefox reports unsupported native WebTransport connection"),
		browserCompatibilityEntry("browser/firefox/webtransport-pin-capability", "firefox", "Firefox reports explicit v3 WebTransport pin capability as unsupported"),
		browserCompatibilityEntry("browser/firefox/websocket/self-contained", "firefox", "Portable browsers run the v3 WebSocket client contract"),
		browserCompatibilityEntry("compat/v2/browser/firefox/websocket/self-contained", "firefox", "Portable browsers run the explicit v2 compatibility WebSocket client contract"),
		browserCompatibilityEntry("compat/v2/browser/webkit/webtransport-capability", "webkit", "WebKit reports unsupported native WebTransport DATAGRAM surface"),
		browserCompatibilityEntry("browser/webkit/webtransport-pin-capability", "webkit", "WebKit reports explicit v3 WebTransport pin capability as unsupported"),
		browserCompatibilityEntry("browser/webkit/websocket/self-contained", "webkit", "Portable browsers run the v3 WebSocket client contract"),
		browserCompatibilityEntry("compat/v2/browser/webkit/websocket/self-contained", "webkit", "Portable browsers run the explicit v2 compatibility WebSocket client contract"),
		commandEntry("coverage/go", "coverage-race", 10*time.Minute, "make", "go-cover-check"),
		commandEntry("coverage/typescript", "coverage-race", 10*time.Minute, "make", "ts-cover-check"),
		commandEntry("coverage/rust", "coverage-race", 10*time.Minute, "make", "rust-cover-check"),
		commandEntry("coverage/swift", "coverage-race", 10*time.Minute, "make", "swift-test", "swift-cover-check"),
		commandEntry("race/go", "coverage-race", 10*time.Minute, "make", "go-test-race"),
		requiredGoTestEntry("diagnostic/weaknet/raw-quic/direct", "TestWeaknetRawQUICSmoke", "./internal/weaknetsmoke", []string{"FLOWERSEC_RUN_WEAKNET_SMOKE=1"}),
		requiredGoTestEntry("diagnostic/weaknet/websocket/direct", "TestWeaknetWebSocketSmoke", "./internal/weaknetsmoke", []string{"FLOWERSEC_RUN_WEAKNET_SMOKE=1"}),
		privilegedGoTestEntry("diagnostic/kernel/topology-lifecycle", "TestPrivilegedTopologyLifecycle"),
		privilegedGoTestEntry("diagnostic/kernel/fault-schedules", "TestPrivilegedExactFaultSchedules"),
		privilegedGoTestEntry("diagnostic/kernel/reorder-duplicate-outage", "TestPrivilegedReorderDuplicateAndOutage"),
		privilegedGoTestEntry("diagnostic/kernel/socket-traversal", "TestPrivilegedGoSocketsTraverseNamespaces"),
	}
	// Keep every required weak-network coordinate as a literal registry entry.
	// The architecture checker consumes these IDs statically and must not have
	// to execute Go loops to discover production test coverage.
	tests = append(tests,
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/websocket/delay-jitter", "websocket", "direct", "delay-jitter"),
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/websocket/periodic-loss", "websocket", "direct", "periodic-loss"),
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/websocket/reorder", "websocket", "direct", "reorder"),
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/websocket/outage-reconnect", "websocket", "direct", "outage-reconnect"),
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/websocket/pin-rotation-refresh-backoff-lease", "websocket", "direct", "pin-rotation-refresh-backoff-lease"),
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/raw-quic/delay-jitter", "raw-quic", "direct", "delay-jitter"),
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/raw-quic/periodic-loss", "raw-quic", "direct", "periodic-loss"),
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/raw-quic/reorder", "raw-quic", "direct", "reorder"),
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/raw-quic/outage-reconnect", "raw-quic", "direct", "outage-reconnect"),
		flowersecWeaknetEntry("diagnostic/flowersec-v3-controller-weaknet/raw-quic/pin-rotation-refresh-backoff-lease", "raw-quic", "direct", "pin-rotation-refresh-backoff-lease"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/websocket/direct/delay-jitter", "websocket", "direct", "delay-jitter"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/websocket/direct/periodic-loss", "websocket", "direct", "periodic-loss"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/websocket/direct/burst-loss", "websocket", "direct", "burst-loss"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/websocket/direct/outage", "websocket", "direct", "outage"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/websocket/direct/mtu-large-payload", "websocket", "direct", "mtu-large-payload"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/websocket/direct/rate-5mbps", "websocket", "direct", "rate-5mbps"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/websocket/direct/rate-1mbps", "websocket", "direct", "rate-1mbps"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/websocket/direct/reorder-duplicate", "websocket", "direct", "reorder-duplicate"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/websocket/tunnel/representative", "websocket", "tunnel", "representative"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/raw-quic/direct/delay-jitter", "raw-quic", "direct", "delay-jitter"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/raw-quic/direct/periodic-loss", "raw-quic", "direct", "periodic-loss"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/raw-quic/direct/burst-loss", "raw-quic", "direct", "burst-loss"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/raw-quic/direct/outage", "raw-quic", "direct", "outage"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/raw-quic/direct/mtu-large-payload", "raw-quic", "direct", "mtu-large-payload"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/raw-quic/direct/rate-5mbps", "raw-quic", "direct", "rate-5mbps"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/raw-quic/direct/rate-1mbps", "raw-quic", "direct", "rate-1mbps"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/raw-quic/direct/reorder-duplicate", "raw-quic", "direct", "reorder-duplicate"),
		flowersecWeaknetEntry("diagnostic/flowersec-weaknet/raw-quic/tunnel/representative", "raw-quic", "tunnel", "representative"),
	)
	if runtime.GOOS == "darwin" {
		tests = append(tests,
			commandEntry("connector/swift-v3", "acceptance", 5*time.Minute, "swift", "test", "--package-path", "flowersec-swift", "--filter", "ConnectorV2Tests/testProductionV3"),
			commandEntryWithEnvironment("connector/swift-v3/interop/swift-go/wss/direct", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CLIENT_PROFILE=swift", "FLOWERSEC_PARITY_TEST_ID=interop/swift-go/wss/direct"}, "node", "scripts/test-server-parity-direct.mjs"),
			commandEntry("controller/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectionControllerTests"),
			commandEntry("compat/v2/controller/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectionControllerV2Tests"),
			commandEntry("protocol/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "TransportV3|IDNAHostV3"),
			commandEntry("compat/v2/protocol/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "TransportV2|IDNAHostV2|SecurityNegativeVectors"),
			commandEntry("compat/v2/controller/swift-real-network-restart", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectorV2Tests/testConnectionControllerV2ReplacesTerminatedGoWSSSessionWithoutReplay"),
			commandEntry("compat/v2/interop/swift-go/wss/direct", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectorV2Tests/testRealGoWSSDirectEndToEnd"),
			commandEntryWithEnvironment("compat/v2/interop/swift-via-go-to-rust/wss/tunnel", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CLIENT_PROFILE=swift", "FLOWERSEC_PARITY_TEST_ID=compat/v2/interop/swift-via-go-to-rust/wss/tunnel"}, "node", "scripts/test-server-parity-tunnel.mjs"),
			commandEntry("compat/v2/carrier/swift-loopback-plaintext-direct", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectorV2Tests/testLoopbackPlaintextDirectRuntimeContract"),
		)
	}
	for _, id := range []string{
		"CAP-DIRECT-WSS-1000", "CAP-DIRECT-QUIC-1000",
		"CAP-WW-1000", "CAP-QQ-1000", "CAP-WQ-1000", "CAP-QW-1000",
	} {
		tests = append(tests, performanceCapacityEntry("performance/capacity/"+strings.ToLower(id), "performance", id))
	}
	for _, id := range []string{
		"CAP-DIRECT-WT-1000", "CAP-TUNNEL-WT-WSS-1000", "CAP-TUNNEL-WT-QUIC-1000",
		"CAP-STREAM-WT-DIRECT-100X128", "CAP-STREAM-WT-WSS-100X128", "CAP-STREAM-WT-QUIC-100X128",
	} {
		if id == "CAP-DIRECT-WT-1000" {
			tests = append(tests, commandEntry("performance-optional/webtransport-capability", "performance-optional", time.Minute,
				"node", "flowersec-ts/scripts/browser-test-runner.mjs", "--runtime-canary", os.Getenv("FLOWERSEC_CHROMIUM_EXECUTABLE")))
		}
		tests = append(tests, performanceCapacityEntry("performance/capacity/"+strings.ToLower(id), "performance-optional", id))
	}
	tests = append(tests, requiredPerformanceGoTestEntry("performance/soak", "performance", "TestFocusedProductionSoakCase", []string{"FLOWERSEC_TEST_SOAK=1", "FLOWERSEC_REQUIRED_PERFORMANCE=1"}, 10*time.Minute))
	tests = append(tests,
		carrierSoakEntry("performance/soak/wss", "performance", "websocket"),
		carrierSoakEntry("performance/soak/webtransport", "performance-optional", "webtransport"),
		throughputEntry("performance/single-connection/wss", "performance", "websocket", "single-connection", 2*time.Minute),
		throughputEntry("performance/single-connection/raw-quic", "performance", "raw-quic", "single-connection", 2*time.Minute),
		throughputEntry("performance/throughput/wss", "performance", "websocket", "streaming", 5*time.Minute),
		throughputEntry("performance/throughput/raw-quic", "performance", "raw-quic", "streaming", 5*time.Minute),
		throughputEntry("performance/single-connection/webtransport", "performance-optional", "webtransport", "single-connection", 2*time.Minute),
		throughputEntry("performance/throughput/webtransport", "performance-optional", "webtransport", "streaming", 5*time.Minute),
	)
	return tests
}

func flowersecWeaknetEntry(id, carrierName, path, scenario string) registeredTest {
	return requiredGoTestEntry(id, "TestPrivilegedFlowersecWeaknet", "./internal/transporttest/flowersecweaknet", []string{
		"FLOWERSEC_LINUX_NETLAB_INTEGRATION=1",
		"FLOWERSEC_WEAKNET_CARRIER=" + carrierName,
		"FLOWERSEC_WEAKNET_PATH=" + path,
		"FLOWERSEC_WEAKNET_SCENARIO=" + scenario,
	})
}

func throughputEntry(id, suite, kind, mode string, timeout time.Duration) registeredTest {
	return requiredPerformanceGoTestEntry(id, suite, "TestFocusedProductionPayloadThroughputCase", []string{"FLOWERSEC_TEST_THROUGHPUT_CARRIER=" + kind, "FLOWERSEC_TEST_THROUGHPUT_MODE=" + mode, "FLOWERSEC_TEST_CASE_ID=" + id}, timeout)
}

func performanceCapacityEntry(id, suite, caseID string) registeredTest {
	return registeredTest{ID: id, Suite: suite, Timeout: 5 * time.Minute, Run: func(ctx context.Context, run runContext) error {
		arguments := []string{"-C", "flowersec-go", "test", "-json", "-timeout=5m", "-count=1", "-run", "^TestFocusedProductionCapacityCase$", "./internal/transporttest/performance"}
		environment := append(performanceCapacityEnvironment(caseID), performanceBudgetEnvironment(run.PerformanceBudget)...)
		environment = append(environment, "FLOWERSEC_TEST_RESULT_PATH="+run.ResultPath)
		return runRequiredGoTest(ctx, run.Root, withRunID(environment, run.RunID), arguments, "./internal/transporttest/performance", "TestFocusedProductionCapacityCase")
	}}
}

func performanceCapacityEnvironment(caseID string) []string {
	return []string{"FLOWERSEC_TEST_CAPACITY_CASE=" + caseID}
}

func carrierSoakEntry(id, suite, kind string) registeredTest {
	environment := []string{"FLOWERSEC_TEST_SOAK=1", "FLOWERSEC_TEST_SOAK_CARRIER=" + kind}
	if suite == "performance" {
		environment = append(environment, "FLOWERSEC_REQUIRED_PERFORMANCE=1")
	}
	return requiredPerformanceGoTestEntry(id, suite, "TestFocusedProductionCarrierSoakCase", environment, 10*time.Minute)
}

func requiredPerformanceGoTestEntry(id, suite, testName string, environment []string, timeout time.Duration) registeredTest {
	return registeredTest{ID: id, Suite: suite, Timeout: timeout, Run: func(ctx context.Context, run runContext) error {
		arguments := []string{"-C", "flowersec-go", "test", "-json", "-timeout=" + timeout.String(), "-count=1", "-run", "^" + regexp.QuoteMeta(testName) + "$", "./internal/transporttest/performance"}
		caseEnvironment := append(append([]string(nil), environment...), performanceBudgetEnvironment(run.PerformanceBudget)...)
		caseEnvironment = append(caseEnvironment, "FLOWERSEC_TEST_RESULT_PATH="+run.ResultPath)
		return runRequiredGoTest(ctx, run.Root, withRunID(caseEnvironment, run.RunID), arguments, "./internal/transporttest/performance", testName)
	}}
}

func withRunID(environment []string, runID string) []string {
	return append(append([]string(nil), environment...), "FLOWERSEC_TEST_RUN_ID="+runID)
}

func browserSmokeEntry(id, title string) registeredTest {
	return commandEntry(id, "browser-smoke", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "run", "test:browser:chromium", "--", "--grep", playwrightTitle(title))
}

func browserClientProfileEntry(id, cell string) registeredTest {
	script := "scripts/test-server-parity-direct.mjs"
	switch cell {
	case "go/direct", "node/direct":
	case "via-go-to-rust/tunnel":
		script = "scripts/test-server-parity-tunnel.mjs"
	default:
		panic("unknown browser client profile cell: " + cell)
	}
	return commandEntryWithEnvironment(id, "browser-smoke", 10*time.Minute,
		[]string{"FLOWERSEC_PARITY_CLIENT_PROFILE=browser", "FLOWERSEC_PARITY_TEST_ID=" + id},
		"node", script)
}

func browserCompatibilityEntry(id, browser, title string) registeredTest {
	return commandEntry(id, "browser-compat", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "run", "test:browser:"+browser, "--", "--grep", playwrightTitle(title))
}

func playwrightTitle(title string) string { return regexp.QuoteMeta(title) }

func privilegedGoTestEntry(id, testName string) registeredTest {
	return requiredGoTestEntry(id, testName, "./internal/transporttest/linuxnetlab", []string{"FLOWERSEC_LINUX_NETLAB_INTEGRATION=1", "FLOWERSEC_REQUIRED_DIAGNOSTIC=1"})
}

func requiredGoTestEntry(id, testName, packageName string, environment []string) registeredTest {
	return registeredTest{ID: id, Suite: "diagnostic", Timeout: 5 * time.Minute, Run: func(ctx context.Context, run runContext) error {
		args := []string{"-C", "flowersec-go", "test", "-json", "-timeout=5m", "-count=1", "-run", "^" + regexp.QuoteMeta(testName) + "$", packageName}
		return runRequiredGoTest(ctx, run.Root, withRunID(append(environment, "FLOWERSEC_REQUIRED_DIAGNOSTIC=1"), run.RunID), args, packageName, testName)
	}}
}

func vitestEntry(id, suite, file, title string) registeredTest {
	return commandEntry(id, suite, 5*time.Minute, "npm", vitestArguments(file, title)...)
}

func vitestArguments(file, title string) []string {
	arguments := []string{"--prefix", "flowersec-ts", "exec", "--", "vitest", "run", "--root", "flowersec-ts", "--config", "vitest.config.ts", file}
	if title != "" {
		arguments = append(arguments, "-t", exactTitle(title))
	}
	return arguments
}

func exactTitle(title string) string {
	return "(^|\\s)" + regexp.QuoteMeta(title) + "$"
}

func commandEntry(id, suite string, timeout time.Duration, command string, arguments ...string) registeredTest {
	return commandEntryWithEnvironment(id, suite, timeout, nil, command, arguments...)
}

func commandEntryWithEnvironment(id, suite string, timeout time.Duration, environment []string, command string, arguments ...string) registeredTest {
	return registeredTest{ID: id, Suite: suite, Timeout: timeout, Run: func(ctx context.Context, run runContext) error {
		return runCommand(ctx, run.Root, withRunID(environment, run.RunID), command, arguments...)
	}}
}

func runCommand(ctx context.Context, directory string, environment []string, name string, arguments ...string) error {
	_, err := runCommandOutput(ctx, directory, environment, name, arguments...)
	return err
}

func runCommandOutput(ctx context.Context, directory string, environment []string, name string, arguments ...string) ([]byte, error) {
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), environment...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output tailBuffer
	output.limit = 64 << 10
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %s", name, err, output.String())
		}
		return append([]byte(nil), output.Bytes()...), nil
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		err, drained := waitForCommandGroup(command.Process.Pid, done, 5*time.Second)
		if !drained {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			if err == nil {
				err = <-done
			}
			return nil, errors.Join(context.Cause(ctx), err, errors.New("subprocess group did not finish teardown after SIGTERM"), errors.New(output.String()))
		}
		return nil, errors.Join(context.Cause(ctx), err, errors.New(output.String()))
	}
}

type goTestOutputEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
}

func runRequiredGoTest(ctx context.Context, directory string, environment, arguments []string, packageName, testName string) error {
	output, err := runCommandOutput(ctx, directory, environment, "go", arguments...)
	if err != nil {
		return err
	}
	return validateRequiredGoTestOutput(output, packageName, testName)
}

func validateRequiredGoTestOutput(output []byte, packageName, testName string) error {
	if strings.TrimSpace(packageName) == "" || strings.TrimSpace(testName) == "" {
		return errors.New("required Go test identity is empty")
	}
	passed := false
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var event goTestOutputEvent
		if json.Unmarshal(scanner.Bytes(), &event) != nil || !matchesGoTestPackage(event.Package, packageName) ||
			(event.Test != testName && !strings.HasPrefix(event.Test, testName+"/")) {
			continue
		}
		switch event.Action {
		case "skip":
			return fmt.Errorf("required Go test %s skipped", testName)
		case "fail":
			return fmt.Errorf("required Go test %s failed", testName)
		case "pass":
			if event.Test == testName {
				passed = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse required Go test output: %w", err)
	}
	if !passed {
		return fmt.Errorf("required Go test %s did not execute to completion", testName)
	}
	return nil
}

func matchesGoTestPackage(actual, expected string) bool {
	if actual == expected {
		return true
	}
	expected = strings.TrimPrefix(expected, "./")
	return expected != "" && strings.HasSuffix(actual, "/"+expected)
}

func waitForCommandGroup(processGroup int, done <-chan error, grace time.Duration) (error, bool) {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var processErr error
	processDone := false
	for {
		if processDone && processGroupFinished(processGroup) {
			return processErr, true
		}
		select {
		case processErr = <-done:
			processDone = true
		case <-ticker.C:
		case <-timer.C:
			return processErr, false
		}
	}
}

func processGroupFinished(processGroup int) bool {
	err := syscall.Kill(-processGroup, 0)
	return errors.Is(err, syscall.ESRCH)
}

type tailBuffer struct {
	bytes.Buffer
	limit int
}

func (buffer *tailBuffer) Write(value []byte) (int, error) {
	written, err := buffer.Buffer.Write(value)
	if buffer.Len() > buffer.limit {
		retained := append([]byte(nil), buffer.Bytes()[buffer.Len()-buffer.limit:]...)
		buffer.Reset()
		_, _ = buffer.Buffer.Write(retained)
	}
	return written, err
}

func (buffer *tailBuffer) String() string {
	return strings.TrimSpace(buffer.Buffer.String())
}
