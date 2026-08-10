package main

import (
	"bytes"
	"context"
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
		vitestEntry("controller/typescript", "acceptance", "src/connectionController.vectors.test.ts", ""),
		vitestEntry("controller/typescript-real-network-restart", "acceptance", "src/node/connectionController.integration.test.ts", "restarts a WSS peer with a fresh lease and does not replay old operations"),
		commandEntry("controller/rust", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connection_controller::tests"),
		commandEntry("controller/rust-raw-quic", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connection_controller_replaces_terminated_raw_quic_session_without_replay"),
		commandEntry("protocol/go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "./internal/protocolv2", "./internal/artifactv2", "./internal/admissionv2", "./internal/session"),
		commandEntry("protocol/typescript", "acceptance", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "test", "--", "--run", "src/v2"),
		commandEntry("protocol/rust", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib"),
		commandEntry("server/go-acceptor", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestAcceptor", "."),
		commandEntry("server/go-rpc-notification", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^Test(SessionHandlersNotificationRegistrationIsBoundedAndFrozen|PublicRPCPeerAndSessionHandlersExposeNotifications)$", "."),
		commandEntry("server/go-controlplane", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "./controlplane"),
		commandEntry("server/go-proxy", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProxyServer", "."),
		vitestEntry("server/typescript-acceptor", "acceptance", "src/node/acceptor.integration.test.ts", "freezes handlers before direct WebTransport establishment"),
		vitestEntry("server/typescript-rpc-notification", "acceptance", "src/node/acceptor.test.ts", "keeps notification registrations isolated from request handlers and freezes them"),
		vitestEntry("server/typescript-proxy", "acceptance", "src/proxy/contract.test.ts", ""),
		commandEntry("server/rust-acceptor", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "public_acceptor_establishes_opaque_direct_session"),
		commandEntry("server/rust-acceptor-handlers", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "public_acceptor_freezes_rpc_and_stream_handlers_before_establishment"),
		commandEntry("carrier/go-direct", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProductDirectCarriersUsePublicConnectorAndAdmission$", "./internal/transporttest"),
		commandEntry("carrier/go-loopback-plaintext-direct", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^(TestAcceptorEstablishesPlaintextLoopbackDirectSession|TestValidateReadyAllowsPlaintextOnlyForLoopbackDirect)$", ".", "./internal/carrier/websocket"),
		vitestEntry("carrier/typescript-loopback-plaintext-direct", "acceptance", "src/node/connectSession.integration.test.ts", "establishes a complete direct session over plaintext loopback"),
		commandEntry("carrier/rust-loopback-plaintext-unsupported", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "transport_v2::tests::native_capabilities_match_the_strict_shared_vector", "--", "--exact"),
		commandEntry("carrier/go-tunnel", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProductionTunnelCarrierCartesianMatrixCarriesEncryptedSessions$", "./internal/tunnelv2"),
		vitestEntry("integration/typescript/node-webtransport", "acceptance", "src/node/webTransport.integration.test.ts", "carries native stream FIN and DATAGRAM without a browser"),
		vitestEntry("interop/typescript-go/wss/direct", "acceptance", "src/interop/goSession.integration.test.ts", "runs direct admission and Session semantics over WSS"),
		vitestEntry("interop/typescript-go/wss/tunnel", "acceptance", "src/interop/goSession.integration.test.ts", "runs tunnel admission and Session semantics over WSS"),
		vitestEntry("interop/typescript-go/webtransport/direct", "acceptance", "src/node/webTransport.integration.test.ts", "runs direct Go admission and Session semantics over WebTransport"),
		vitestEntry("interop/typescript-go/webtransport/tunnel", "acceptance", "src/node/webTransport.integration.test.ts", "runs tunnel Go admission and Session semantics over WebTransport"),
		commandEntry("interop/rust-go/raw-quic/direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "rust_and_go_run_full_session_v2_over_raw_quic_direct", "--", "--exact"),
		commandEntry("interop/rust-go/raw-quic/tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "rust_and_go_run_full_session_v2_over_raw_quic_tunnel", "--", "--exact"),
		commandEntry("interop/go-rust/raw-quic/direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "raw_quic_v2_integration_tests::go_client_to_rust_server_runs_admission_over_native_quic_direct", "--", "--exact"),
		commandEntry("interop/go-rust/raw-quic/tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "raw_quic_v2_integration_tests::go_client_to_rust_server_runs_admission_over_native_quic_tunnel", "--", "--exact"),
		browserSmokeEntry("browser/chromium/webtransport/direct", "Chromium runs the direct WebTransport topology"),
		browserSmokeEntry("browser/chromium-tunnel-wt-wss", "Chromium WebTransport tunnel bridges to production Go wss"),
		browserSmokeEntry("browser/chromium-tunnel-wt-quic", "Chromium WebTransport tunnel bridges to production Go raw_quic"),
		browserCompatibilityEntry("browser/firefox/webtransport-capability", "firefox", "Firefox reports unsupported native WebTransport connection"),
		browserCompatibilityEntry("browser/webkit/webtransport-capability", "webkit", "WebKit reports unsupported native WebTransport DATAGRAM surface"),
		commandEntry("coverage/go", "coverage-race", 10*time.Minute, "make", "go-cover-check"),
		commandEntry("coverage/typescript", "coverage-race", 10*time.Minute, "make", "ts-cover-check"),
		commandEntry("coverage/rust", "coverage-race", 10*time.Minute, "make", "rust-cover-check"),
		commandEntry("coverage/swift", "coverage-race", 10*time.Minute, "make", "swift-test", "swift-cover-check"),
		commandEntry("race/go", "coverage-race", 10*time.Minute, "make", "go-test-race"),
		commandEntryWithEnvironment("diagnostic/weaknet/raw-quic/direct", "diagnostic", 5*time.Minute, []string{"FLOWERSEC_RUN_WEAKNET_SMOKE=1"}, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestWeaknetRawQUICSmoke$", "./internal/weaknetsmoke"),
		commandEntryWithEnvironment("diagnostic/weaknet/websocket/direct", "diagnostic", 5*time.Minute, []string{"FLOWERSEC_RUN_WEAKNET_SMOKE=1"}, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestWeaknetWebSocketSmoke$", "./internal/weaknetsmoke"),
		privilegedGoTestEntry("diagnostic/kernel/topology-lifecycle", "TestPrivilegedTopologyLifecycle"),
		privilegedGoTestEntry("diagnostic/kernel/fault-schedules", "TestPrivilegedExactFaultSchedules"),
		privilegedGoTestEntry("diagnostic/kernel/reorder-duplicate-outage", "TestPrivilegedReorderDuplicateAndOutage"),
		privilegedGoTestEntry("diagnostic/kernel/socket-traversal", "TestPrivilegedGoSocketsTraverseNamespaces"),
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		tests = append(tests,
			commandEntry("controller/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectionController"),
			commandEntry("controller/swift-real-network-restart", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectorV2Tests/testConnectionControllerReplacesTerminatedGoWSSessionWithoutReplay"),
			commandEntry("protocol/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "TransportV2|IDNAHostV2|SecurityNegativeVectors"),
			commandEntry("interop/swift-go/wss/direct", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectorV2Tests/testRealGoWSSDirectEndToEnd"),
			commandEntry("interop/swift-go/wss/tunnel", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectorV2Tests/testRealGoWSSTunnelEndToEnd"),
			commandEntry("carrier/swift-loopback-plaintext-direct", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectorV2Tests/testLoopbackPlaintextDirectRuntimeContract"),
		)
	}
	for _, id := range []string{
		"CAP-DIRECT-WSS-1000", "CAP-DIRECT-QUIC-1000", "CAP-DIRECT-WT-1000",
		"CAP-TUNNEL-WT-WSS-1000", "CAP-TUNNEL-WT-QUIC-1000",
		"CAP-STREAM-WT-DIRECT-100X128", "CAP-STREAM-WT-WSS-100X128", "CAP-STREAM-WT-QUIC-100X128",
		"CAP-WW-1000", "CAP-QQ-1000", "CAP-WQ-1000", "CAP-QW-1000",
	} {
		tests = append(tests, performanceCapacityEntry("performance/capacity/"+strings.ToLower(id), id))
	}
	tests = append(tests, commandEntryWithEnvironment("performance/soak", "performance", 10*time.Minute, []string{"FLOWERSEC_TEST_SOAK=1"}, "go", "-C", "flowersec-go", "test", "-timeout=10m", "-count=1", "-run", "^TestFocusedProductionSoakCase$", "./internal/transporttest/performance"))
	tests = append(tests,
		carrierSoakEntry("performance/soak/wss", "websocket"),
		carrierSoakEntry("performance/soak/webtransport", "webtransport"),
	)
	return tests
}

func performanceCapacityEntry(id, caseID string) registeredTest {
	return registeredTest{ID: id, Suite: "performance", Timeout: 5 * time.Minute, Run: func(ctx context.Context, run runContext) error {
		return runCommand(ctx, run.Root, withRunID(performanceCapacityEnvironment(caseID), run.RunID), "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestFocusedProductionCapacityCase$", "./internal/transporttest/performance")
	}}
}

func performanceCapacityEnvironment(caseID string) []string {
	return []string{"FLOWERSEC_TEST_CAPACITY_CASE=" + caseID}
}

func carrierSoakEntry(id, kind string) registeredTest {
	return commandEntryWithEnvironment(id, "performance", 10*time.Minute,
		[]string{"FLOWERSEC_TEST_SOAK=1", "FLOWERSEC_TEST_SOAK_CARRIER=" + kind},
		"go", "-C", "flowersec-go", "test", "-timeout=10m", "-count=1", "-run", "^TestFocusedProductionCarrierSoakCase$", "./internal/transporttest/performance")
}

func withRunID(environment []string, runID string) []string {
	return append(append([]string(nil), environment...), "FLOWERSEC_TEST_RUN_ID="+runID)
}

func browserSmokeEntry(id, title string) registeredTest {
	return commandEntry(id, "browser-smoke", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "run", "test:browser:chromium", "--", "--grep", playwrightTitle(title))
}

func browserCompatibilityEntry(id, browser, title string) registeredTest {
	return commandEntry(id, "browser-compat", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "run", "test:browser:"+browser, "--", "--grep", playwrightTitle(title))
}

func playwrightTitle(title string) string { return regexp.QuoteMeta(title) }

func privilegedGoTestEntry(id, testName string) registeredTest {
	return commandEntryWithEnvironment(id, "diagnostic", 5*time.Minute, []string{"FLOWERSEC_LINUX_NETLAB_INTEGRATION=1"},
		"go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^"+regexp.QuoteMeta(testName)+"$", "./internal/transporttest/linuxnetlab")
}

func vitestEntry(id, suite, file, title string) registeredTest {
	return commandEntry(id, suite, 5*time.Minute, "npm", vitestArguments(file, title)...)
}

func vitestArguments(file, title string) []string {
	arguments := []string{"--prefix", "flowersec-ts", "exec", "--", "vitest", "run", "--config", "flowersec-ts/vitest.config.ts", "flowersec-ts/" + file}
	if title != "" {
		arguments = append(arguments, "-t", exactTitle(title))
	}
	return arguments
}

func exactTitle(title string) string {
	return "^" + regexp.QuoteMeta(title) + "$"
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
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), environment...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output tailBuffer
	output.limit = 64 << 10
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%s: %w: %s", name, err, output.String())
		}
		return nil
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		err, drained := waitForCommandGroup(command.Process.Pid, done, 5*time.Second)
		if !drained {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			if err == nil {
				err = <-done
			}
			return errors.Join(context.Cause(ctx), err, errors.New("subprocess group did not finish teardown after SIGTERM"), errors.New(output.String()))
		}
		return errors.Join(context.Cause(ctx), err, errors.New(output.String()))
	}
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
