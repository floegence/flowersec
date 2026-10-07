package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const goAcceptorTestPattern = "^Test(ProductDirect(CarriersUsePublicConnectorAndAdmission|EndpointReusesListenerForConcurrentArtifacts|WebTransportUpgradeFailure|WebTransportAdmissionFailure|BrowserArtifactsAreFreshAndCancelable)|CurrentDirect(CanceledAcceptance|Interruption))"

func registry() []registeredTest {
	return registryForOS(runtime.GOOS)
}

func registryForOS(goos string) []registeredTest {
	tests := []registeredTest{
		commandEntry("protocol/v4-admission-sqlite-go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^Test(SQLite|AcceptedAdmission|AdmissionFacts)", "./internal/ledgerv4", "./internal/sessionv4", "./internal/protocolv4"),
		commandEntry("protocol/v4-cbor-go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^(TestCBOR|FuzzCBORReference)", "./internal/protocolv4"),
		commandEntry("protocol/v4-rekey-go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestV4Rekey", "./internal/protocolv4"),
		commandEntry("protocol/v4-rekey-rust", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--locked", "--test", "transport_v4_rekey"),
		vitestEntry("protocol/v4-rekey-typescript", "acceptance", "src/v4/rekeyReference.test.ts", ""),
		commandEntry("protocol/v4-record-go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestV4Record", "./internal/protocolv4"),
		commandEntry("protocol/v4-record-rust", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--locked", "--test", "transport_v4_records"),
		vitestEntry("protocol/v4-record-typescript", "acceptance", "src/v4/recordReference.test.ts", ""),
		commandEntry("protocol/v4-ready-go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestV4Ready", "./internal/protocolv4"),
		commandEntry("protocol/v4-ready-rust", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--locked", "--test", "transport_v4_ready"),
		vitestEntry("protocol/v4-ready-typescript", "acceptance", "src/v4/readyReference.test.ts", ""),
		commandEntry("protocol/v4-noise-go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestV4Noise", "./internal/protocolv4"),
		commandEntry("protocol/v4-noise-rust", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--locked", "--test", "transport_v4_noise"),
		commandEntry("protocol/v4-dh-go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestV4ProfileDHReference$", "./internal/protocolv4"),
		commandEntry("protocol/v4-dh-rust", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--locked", "--test", "transport_v4_profile_dh"),
		vitestEntry("protocol/v4-dh-typescript", "acceptance", "src/v4/profileDHReference.test.ts", ""),
		commandEntry("protocol/v4-strict-go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestV4StrictSignature", "./internal/protocolv4"),
		commandEntry("protocol/v4-strict-rust", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--locked", "--test", "transport_v4_strict_signatures"),
		commandEntry("controller/go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^Test(V4Controller|Controller|CandidateRemote|ExplicitUpdate)", "./internal/sessionv4", "."),
		commandEntry("controller/go-real-network-restart", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestConnectionControllerRealNetworkRestartReconnect$", "./internal/transporttest"),
		commandEntry("controller/go-websocket-handlers", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^Test(ConnectionController(WebSocketHandlersSurviveTwoGenerations|RetriesTLSInterruptionAfterDisconnect)|DynamicNotificationsShareInboundRouter)$", "./internal/transporttest"),
		commandEntry("controller/typescript", "acceptance", 5*time.Minute, "node", "scripts/server-parity-native-addon.mjs", "--vitest", "run", "src/v4/sessionRuntime.test.ts", "src/v4/controllerUnaryRoute.test.ts", "-t", "Controller"),
		commandEntry("controller/rust", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "controller"),
		commandEntry("protocol/go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "./internal/protocolv4", "./internal/cryptov4", "./internal/ledgerv4", "./internal/sessionv4", "./internal/controlv4", "./internal/resourcev4", "./internal/rpcv4", "./internal/idna15", "."),
		commandEntry("protocol/typescript", "acceptance", 5*time.Minute, "node", "scripts/test-ts-unit.mjs", "src/v4"),
		commandEntry("protocol/rust", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib"),
		commandEntry("server/go-acceptor", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", goAcceptorTestPattern, "./internal/transporttest"),
		commandEntry("server/go-rpc-notification", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^Test(Notification|Notify|SessionNotify|RPCServices|DynamicNotifications)", "./internal/sessionv4", "./internal/transporttest"),
		commandEntry("server/go-controlplane", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "./controlplane"),
		commandEntry("server/go-proxy", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProxy", "."),
		installedVitestEntry("server/typescript-proxy", "acceptance", "src/node/proxyServer.integration.test.ts", "forwards HTTP over a real WebSocket Session with bounded policy and cleanup"),
		commandEntry("server/rust-proxy", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--test", "proxy_server_public"),
		installedVitestEntry("server/typescript-acceptor", "acceptance", "src/node/serverRuntimeCurrent.integration.test.ts", "serves immutable accepted-server RPC, notification, and stream declarations after the original plan is sealed"),
		installedVitestEntry("controller/typescript-rpc-handlers-current", "acceptance", "src/node/serverRuntimeCurrent.integration.test.ts", "reuses one immutable client HandlerPlan with fresh routers and original pool issuance across controller generations"),
		commandEntry("server/rust-acceptor", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "crypto_v4::connect::serve::tests::production_listener_durable_admission_and_original_serve_children", "--", "--exact"),
		commandEntry("server/rust-acceptor-handlers", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "crypto_v4::connect::serve::application_tests::application_registered_handler_plan_dispatches_real_io_and_drains_callbacks", "--", "--exact"),
		commandEntry("carrier/go-direct", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProductDirectCarriersUsePublicConnectorAndAdmission$", "./internal/transporttest"),
		commandEntry("carrier/rust-websocket-direct", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "crypto_v4::connect::tests::real_wss_pool_connect_dual_ready_stream_rekey_probe_and_cleanup", "--", "--exact"),
		commandEntryWithEnvironment("carrier/rust-websocket-tunnel", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CARRIERS=websocket", "FLOWERSEC_PARITY_ENDPOINT_AS=go", "FLOWERSEC_PARITY_ENDPOINT_BS=rust", "FLOWERSEC_PARITY_RELAYS=rust"}, "node", "scripts/test-server-parity-tunnel.mjs"),
		commandEntryWithEnvironment("carrier/rust-raw-quic-tunnel", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CARRIERS=raw-quic", "FLOWERSEC_PARITY_ENDPOINT_AS=go", "FLOWERSEC_PARITY_ENDPOINT_BS=rust", "FLOWERSEC_PARITY_RELAYS=rust"}, "node", "scripts/test-server-parity-tunnel.mjs"),
		commandEntry("server/typescript-raw-quic-direct", "acceptance", 10*time.Minute, "node", "scripts/server-parity-native-addon.mjs", "--test-title", "admits direct raw QUIC with original stores, typed RPC, stream FIN, and cleanup (hold DRAINED: false)"),
		nativeTunnelEntry("server/typescript-raw-quic-tunnel"),
		commandEntry("carrier/go-tunnel", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProductionTunnelTopologiesRunColdRPCBulkAndCleanup$", "./internal/transporttest/tunnelworkload"),
		commandEntry("carrier/go-webtransport-tunnel", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestBrowserTunnelTopologiesUseProductionWebTransportBrokerPath$", "./internal/transporttest/tunnelworkload"),
		installedVitestEntry("interop/typescript-go/wss/direct", "acceptance", "src/interop/goSessionCurrent.integration.test.ts", "runs direct original notification/payload/rekey Session semantics over current Go WSS"),
		installedVitestEntry("interop/typescript-go/wss/tunnel", "acceptance", "src/interop/goSessionCurrent.integration.test.ts", "runs tunnel-role original notification/payload/rekey Session semantics through current Go WSS"),
		installedVitestEntry("interop/typescript-go/private-loopback/direct", "acceptance", "src/interop/localBrowserBridgeCurrent.integration.test.ts", "establishes a real Session, performs RPC, spends once, and releases once"),
		installedVitestEntry("interop/typescript-go/http-direct", "acceptance", "src/interop/httpDirectCurrent.integration.test.ts", "shares one application port and preserves two independent sessions"),
		installedVitestEntry("protocol/typescript-http-direct", "acceptance", "src/node/clientV4.test.ts", ""),
		commandEntry("protocol/go-http-direct", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^Test(DirectIssueHTTP|DelegatedHTTP|HTTPStream)", "./internal/protocolv4", "./internal/sessionv4"),
		commandEntry("interop/v4/native/direct/go-baseline", "acceptance", 10*time.Minute, "node", "scripts/test-server-parity-direct.mjs"),
		commandEntry("interop/v4/native/tunnel/go-baseline", "acceptance", 10*time.Minute, "node", "scripts/test-server-parity-tunnel.mjs"),
		commandEntry("examples/public-sdk-e2e", "acceptance", 10*time.Minute, "node", "scripts/test-sdk-examples-e2e.mjs"),
		commandEntryWithEnvironment("interop/rust-go/raw-quic/direct", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CARRIERS=raw-quic", "FLOWERSEC_PARITY_CLIENTS=rust", "FLOWERSEC_PARITY_SERVERS=go"}, "node", "scripts/test-server-parity-direct.mjs"),
		commandEntryWithEnvironment("interop/rust-go/raw-quic/tunnel", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CARRIERS=raw-quic", "FLOWERSEC_PARITY_ENDPOINT_AS=rust", "FLOWERSEC_PARITY_ENDPOINT_BS=go", "FLOWERSEC_PARITY_RELAYS=node-typescript"}, "node", "scripts/test-server-parity-tunnel.mjs"),
		commandEntryWithEnvironment("interop/go-rust/raw-quic/direct", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CARRIERS=raw-quic", "FLOWERSEC_PARITY_CLIENTS=go", "FLOWERSEC_PARITY_SERVERS=rust"}, "node", "scripts/test-server-parity-direct.mjs"),
		commandEntryWithEnvironment("interop/go-rust/raw-quic/tunnel", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CARRIERS=raw-quic", "FLOWERSEC_PARITY_ENDPOINT_AS=go", "FLOWERSEC_PARITY_ENDPOINT_BS=rust", "FLOWERSEC_PARITY_RELAYS=rust"}, "node", "scripts/test-server-parity-tunnel.mjs"),
		commandEntry("carrier/rust-tls13-handshake", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "crypto_v4::connect::tests::real_wss_pool_connect_dual_ready_stream_rekey_probe_and_cleanup", "--", "--exact"),
		commandEntry("carrier/rust-tls-rejection", "acceptance", 5*time.Minute, "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "crypto_v4::connect::tests::invalid_actual_tls_pin_fails_before_pool_spend"),
		commandEntry("carrier/node-native-addon/lifecycle", "acceptance", 10*time.Minute, "make", "native-addon-test"),
		browserSmokeEntry("browser/chromium/webtransport/direct", "Chromium runs current WebTransport with a signed pin, reliable echo and datagram"),
		browserSmokeEntry("browser/chromium/webtransport/pin-rejection", "Chromium WebTransport rejects a signed unknown pin before durable spend"),
		browserSmokeEntry("browser/chromium/webtransport/hash-constructor-unsupported", "Chromium WebTransport fails closed when certificate hashes are unsupported"),
		browserSmokeEntry("browser/chromium/webtransport/ca-policy", "Chromium WebTransport delegates CA trust without hashes and retains normalized deployment URLs"),
		browserSmokeEntry("browser/chromium/webtransport/public-ca", "Chromium WebTransport accepts an actual public-CA deployment"),
		browserSmokeEntry("browser/chromium/webtransport/public-ca-wrong-pin-no-fallback", "Chromium WebTransport rejects a wrong pin on a public-CA endpoint without CA fallback"),
		browserSmokeEntry("browser/chromium/websocket/self-contained", "Portable browsers run the ordinary WebSocket client contract"),
		browserSmokeEntry("browser/chromium/proxy-service-worker", "Chromium runs the Service Worker proxy product chain"),
		commandEntryWithEnvironment("connector/browser-v4/interop/browser-go/wss/direct", "browser-smoke", 10*time.Minute, []string{"FLOWERSEC_PARITY_CLIENT_PROFILE=browser", "FLOWERSEC_PARITY_TEST_ID=interop/browser-go/wss/direct"}, "node", "scripts/test-server-parity-direct.mjs"),
		commandEntryWithEnvironment("connector/browser-v4/interop/browser-go/wss/tunnel", "browser-smoke", 10*time.Minute, []string{"FLOWERSEC_PARITY_CLIENT_PROFILE=browser", "FLOWERSEC_PARITY_TEST_ID=interop/browser-go/wss/tunnel"}, "node", "scripts/test-server-parity-tunnel.mjs"),
		browserCompatibilityEntry("browser/firefox/webtransport-pin-capability", "firefox", "Firefox reports the current WebTransport pin deployment as unsupported"),
		browserCompatibilityEntry("browser/firefox/websocket/self-contained", "firefox", "Portable browsers run the ordinary WebSocket client contract"),
		browserCompatibilityEntry("browser/webkit/webtransport-pin-capability", "webkit", "WebKit reports the current WebTransport pin deployment as unsupported"),
		browserCompatibilityEntry("browser/webkit/websocket/self-contained", "webkit", "Portable browsers run the ordinary WebSocket client contract"),
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
	// A fresh original authority installation is kept alive through the staged
	// Rust relay and actual endpoint SDK cleanup. Pool acceptance is separate.
	tests = append(tests,
		commandEntryWithEnvironment("interop/v4/registered-live-rust-relay", "acceptance", 10*time.Minute,
			[]string{"FLOWERSEC_PARITY_ACTIVATION_SOURCE=live_authority", "FLOWERSEC_PARITY_RELAYS=rust",
				"FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT=", "FLOWERSEC_PARITY_LIVE_DEPLOYMENT=", "FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT=", "FLOWERSEC_PARITY_RELAY_LIVE_DEPLOYMENT=",
				"FLOWERSEC_PARITY_CLIENT_PROFILE=", "FLOWERSEC_PARITY_TEST_ID="},
			"node", "scripts/test-server-parity-tunnel.mjs"),
	)
	// Keep every required weak-network coordinate as a literal registry entry.
	// The architecture checker consumes these IDs statically and must not have
	// to execute Go loops to discover production test coverage.
	tests = append(tests,
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/websocket/delay-jitter", "websocket", "direct", "delay-jitter"),
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/websocket/periodic-loss", "websocket", "direct", "periodic-loss"),
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/websocket/reorder", "websocket", "direct", "reorder"),
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/websocket/outage-reconnect", "websocket", "direct", "outage-reconnect"),
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/websocket/pin-rotation-refresh-backoff-lease", "websocket", "direct", "pin-rotation-refresh-backoff-lease"),
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/raw-quic/delay-jitter", "raw-quic", "direct", "delay-jitter"),
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/raw-quic/periodic-loss", "raw-quic", "direct", "periodic-loss"),
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/raw-quic/reorder", "raw-quic", "direct", "reorder"),
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/raw-quic/outage-reconnect", "raw-quic", "direct", "outage-reconnect"),
		flowersecWeaknetEntry("diagnostic/flowersec-v4-controller-weaknet/raw-quic/pin-rotation-refresh-backoff-lease", "raw-quic", "direct", "pin-rotation-refresh-backoff-lease"),
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
	if goos == "darwin" {
		tests = append(tests,
			commandEntry("protocol/v4-record-swift", "acceptance", 5*time.Minute, "swift", "test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "TransportRecordTests"),
			commandEntry("protocol/v4-ready-swift", "acceptance", 5*time.Minute, "swift", "test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "TransportReadyTests"),
			commandEntry("protocol/v4-rekey-swift", "acceptance", 5*time.Minute, "swift", "test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "TransportRekeyTests"),
			commandEntry("protocol/v4-dh-swift", "acceptance", 5*time.Minute, "swift", "test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "TransportProfileDHTests"),
			commandEntry("protocol/v4-strict-swift", "acceptance", 5*time.Minute, "swift", "test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "TransportStrictSignatureTests"),
			commandEntry("connector/swift-v4", "acceptance", 5*time.Minute, "swift", "test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "TransportNativeSessionTests"),
			commandEntry("controller/swift-client-handlers", "acceptance", 5*time.Minute, "swift", "test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "TransportNativeSessionTests/test(ClientRegisteredHandlers|ControllerRegisteredHandlers|ControllerRefusesSecondReplacementUntilOriginalRetiredNotificationCallbackExits)"),
			commandEntry("controller/swift-client-handlers/ios-simulator", "acceptance", 5*time.Minute, "node", "scripts/run-ios-simulator-test.mjs", "--suite", "client-handlers"),
			commandEntry("connector/swift-v4/ios-simulator", "acceptance", 5*time.Minute, "node", "scripts/run-ios-simulator-test.mjs", "--suite", "connector"),
			commandEntryWithEnvironment("connector/swift-v4/interop/swift-go/wss/direct", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CLIENT_PROFILE=swift", "FLOWERSEC_PARITY_TEST_ID=interop/swift-go/wss/direct"}, "node", "scripts/test-server-parity-direct.mjs"),
			commandEntryWithEnvironment("connector/swift-v4/interop/swift-go/wss/tunnel", "acceptance", 5*time.Minute, []string{"FLOWERSEC_PARITY_CLIENT_PROFILE=swift", "FLOWERSEC_PARITY_TEST_ID=interop/swift-go/wss/tunnel"}, "node", "scripts/test-server-parity-tunnel.mjs"),
			commandEntryWithEnvironment("interop/swift-rust-go/wss/live-tunnel", "acceptance", 10*time.Minute,
				[]string{"FLOWERSEC_PARITY_CLIENT_PROFILE=swift", "FLOWERSEC_PARITY_TEST_ID=interop/swift-rust-go/wss/live-tunnel", "FLOWERSEC_PARITY_ACTIVATION_SOURCE=live_authority",
					"FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT=", "FLOWERSEC_PARITY_LIVE_DEPLOYMENT=", "FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT=", "FLOWERSEC_PARITY_RELAY_LIVE_DEPLOYMENT="},
				"node", "scripts/test-server-parity-tunnel.mjs"),
			commandEntry("server/swift-acceptor", "acceptance", 5*time.Minute, "swift", "test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "TransportOriginalLiveServerTests/test(PoolServerSource|OriginalServerAllow|NativeRelay|TransferredOriginal|CompletedSource|OriginalAdmission)"),
			commandEntry("server/swift-session-handlers", "acceptance", 5*time.Minute, "swift", "test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "TransportOriginalLiveServerTests/testServe|ServiceApplicationOwnershipV4Tests/testServer(Unary|UnknownType|ExecutionNotification)|streamHandlers"),
			commandEntry("server/swift-acceptor/ios-simulator", "acceptance", 5*time.Minute, "node", "scripts/run-ios-simulator-test.mjs", "--suite", "server-acceptor"),
			commandEntry("server/swift-session-handlers/ios-simulator", "acceptance", 5*time.Minute, "node", "scripts/run-ios-simulator-test.mjs", "--suite", "server-session-handlers"),
			commandEntry("controller/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ControllerServiceGenerationTests|ServiceApplicationOwnershipV4Tests/testController"),
			commandEntry("protocol/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "Transport|IDNAHost|ServiceApplication"),
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
			tests = append(tests, chromiumWebTransportPerformanceCapabilityEntry(os.Getenv("FLOWERSEC_CHROMIUM_EXECUTABLE")))
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

// The installed native SQLite extension belongs to the same bounded runner as
// the test process; a globally installed or stale package is never substituted.
func installedVitestEntry(id, suite, file, title string) registeredTest {
	arguments := []string{"scripts/server-parity-native-addon.mjs", "--vitest", "run", file}
	if title != "" {
		arguments = append(arguments, "-t", exactTitle(title))
	}
	return commandEntry(id, suite, 5*time.Minute, "node", arguments...)
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

func chromiumWebTransportPerformanceCapabilityEntry(executable string) registeredTest {
	return registeredTest{
		ID:      "performance-optional/webtransport-capability",
		Suite:   "performance-optional",
		Timeout: time.Minute,
		Run: func(ctx context.Context, run runContext) error {
			output, err := runCommandOutput(ctx, run.Root, withRunID(nil, run.RunID),
				"node", "flowersec-ts/scripts/browser-test-runner.mjs", "--runtime-canary", executable)
			if err != nil {
				return err
			}
			return parseChromiumPerformanceCapability(output)
		},
	}
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
	return runCommandOutputWithGrace(ctx, 5*time.Second, directory, environment, name, arguments...)
}

func runCommandOutputWithGrace(ctx context.Context, grace time.Duration, directory string, environment []string, name string, arguments ...string) ([]byte, error) {
	return runCommandOutputWithGraceAndGroupWait(ctx, grace, waitForProcessGroup, directory, environment, name, arguments...)
}

func runCommandOutputWithGraceAndGroupWait(ctx context.Context, grace time.Duration, groupWait func(int, time.Duration) bool, directory string, environment []string, name string, arguments ...string) ([]byte, error) {
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), environment...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	outputFile, err := os.CreateTemp("", "flowersec-command-output-*")
	if err != nil {
		return nil, fmt.Errorf("create command output file: %w", err)
	}
	outputPath := outputFile.Name()
	defer func() {
		_ = outputFile.Close()
		_ = os.Remove(outputPath)
	}()
	command.Stdout, command.Stderr = outputFile, outputFile
	if err := command.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		cleanupErr := cleanupCommandGroup(command.Process.Pid, 5*time.Second)
		output, outputErr := readCommandOutput(outputFile)
		if outputErr != nil {
			var commandErr error
			if err != nil {
				commandErr = fmt.Errorf("%s: %w", name, err)
			}
			return nil, errors.Join(commandErr, cleanupErr, fmt.Errorf("read %s output: %w", name, outputErr))
		}
		if err != nil || cleanupErr != nil {
			var commandErr error
			if err != nil {
				commandErr = fmt.Errorf("%s: %w", name, err)
			}
			return nil, errors.Join(commandErr, cleanupErr, errors.New(string(output)))
		}
		return output, nil
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		err, processDone, drained := waitForCommandGroup(command.Process.Pid, done, grace)
		if !drained {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			groupFinished := groupWait(command.Process.Pid, grace)
			if !processDone {
				select {
				case err = <-done:
					processDone = true
				case <-time.After(grace):
					return nil, errors.Join(context.Cause(ctx), errors.New("subprocess did not exit after SIGKILL"))
				}
			}
			if !groupFinished {
				return nil, errors.Join(context.Cause(ctx), err, errors.New("subprocess group did not exit after SIGKILL"))
			}
			output, outputErr := readCommandOutput(outputFile)
			if outputErr != nil {
				return nil, errors.Join(context.Cause(ctx), err, outputErr)
			}
			return nil, errors.Join(context.Cause(ctx), err, errors.New("subprocess group did not finish teardown after SIGTERM"), errors.New(string(output)))
		}
		output, outputErr := readCommandOutput(outputFile)
		if outputErr != nil {
			return nil, errors.Join(context.Cause(ctx), err, outputErr)
		}
		return nil, errors.Join(context.Cause(ctx), err, errors.New(string(output)))
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

func waitForCommandGroup(processGroup int, done <-chan error, grace time.Duration) (error, bool, bool) {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var processErr error
	processDone := false
	for {
		if processDone && processGroupFinished(processGroup) {
			return processErr, true, true
		}
		select {
		case processErr = <-done:
			processDone = true
		case <-ticker.C:
		case <-timer.C:
			return processErr, processDone, false
		}
	}
}

func processGroupFinished(processGroup int) bool {
	err := syscall.Kill(-processGroup, 0)
	return errors.Is(err, syscall.ESRCH)
}

func cleanupCommandGroup(processGroup int, grace time.Duration) error {
	if processGroupFinished(processGroup) {
		return nil
	}
	_ = syscall.Kill(-processGroup, syscall.SIGTERM)
	if waitForProcessGroup(processGroup, grace) {
		return nil
	}
	_ = syscall.Kill(-processGroup, syscall.SIGKILL)
	if waitForProcessGroup(processGroup, grace) {
		return nil
	}
	return errors.New("subprocess group did not finish teardown after command exit")
}

func waitForProcessGroup(processGroup int, grace time.Duration) bool {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if processGroupFinished(processGroup) {
			return true
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return false
		}
	}
}

func readCommandOutput(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	offset := info.Size() - 64<<10
	if offset < 0 {
		offset = 0
	}
	if _, err := file.Seek(offset, 0); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, 64<<10))
}
