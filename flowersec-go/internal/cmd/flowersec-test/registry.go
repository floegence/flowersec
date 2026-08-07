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
		vitestEntry("controller/typescript", "acceptance", "src/connectionController.vectors.test.ts", ""),
		commandEntry("controller/rust", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connection_controller::tests"),
		commandEntry("controller/rust-raw-quic", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "connection_controller_replaces_terminated_raw_quic_session_without_replay"),
		commandEntry("protocol/go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "./internal/protocolv2", "./internal/artifactv2", "./internal/admissionv2", "./internal/session"),
		commandEntry("protocol/typescript", "acceptance", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "test", "--", "--run", "src/v2"),
		commandEntry("protocol/rust", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--test", "transport_v2_contract"),
		commandEntry("carrier/go-direct", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProductDirectCarriersUsePublicConnectorAndAdmission$", "./internal/transporttest"),
		commandEntry("carrier/go-tunnel", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestProductionTunnelCarrierCartesianMatrixCarriesEncryptedSessions$", "./internal/tunnelv2"),
		vitestEntry("integration/typescript/node-webtransport", "acceptance", "src/node/webTransport.integration.test.ts", "carries native stream FIN and DATAGRAM without a browser"),
		vitestEntry("interop/typescript-go/wss/direct", "acceptance", "src/interop/goSession.integration.test.ts", "runs direct admission and Session semantics over WSS"),
		vitestEntry("interop/typescript-go/wss/tunnel", "acceptance", "src/interop/goSession.integration.test.ts", "runs tunnel admission and Session semantics over WSS"),
		vitestEntry("interop/typescript-go/webtransport/direct", "acceptance", "src/node/webTransport.integration.test.ts", "runs direct Go admission and Session semantics over WebTransport"),
		vitestEntry("interop/typescript-go/webtransport/tunnel", "acceptance", "src/node/webTransport.integration.test.ts", "runs tunnel Go admission and Session semantics over WebTransport"),
		commandEntry("interop/rust-go/raw-quic/direct", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "rust_and_go_run_full_session_v2_over_raw_quic_direct", "--", "--exact"),
		commandEntry("interop/rust-go/raw-quic/tunnel", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "rust_and_go_run_full_session_v2_over_raw_quic_tunnel", "--", "--exact"),
		browserSmokeEntry("browser/chromium/webtransport/direct", "Chromium runs the direct WebTransport topology"),
		browserSmokeEntry("browser/chromium-tunnel-wt-wss", "Chromium WebTransport tunnel bridges to production Go wss"),
		browserSmokeEntry("browser/chromium-tunnel-wt-quic", "Chromium WebTransport tunnel bridges to production Go raw_quic"),
		commandEntry("diagnostic/protocol", "diagnostic", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "./internal/protocolv2", "./internal/artifactv2", "./internal/admissionv2", "./internal/session", "./internal/transporttest"),
		commandEntry("diagnostic/browser", "diagnostic", 10*time.Minute, "npm", "--prefix", "flowersec-ts", "run", "test:browser"),
		vitestEntry("diagnostic/interop", "diagnostic", "src/interop/goSession.integration.test.ts", ""),
		commandEntryWithEnvironment("diagnostic/weaknet", "diagnostic", 5*time.Minute, []string{"FLOWERSEC_RUN_WEAKNET_SMOKE=1"}, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "./internal/weaknet", "./internal/weaknetsmoke"),
		commandEntryWithEnvironment("diagnostic/kernel-outage", "diagnostic", 5*time.Minute, []string{"FLOWERSEC_LINUX_NETLAB_INTEGRATION=1"}, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestPrivilegedReorderDuplicateAndOutage$", "./internal/transporttest/linuxnetlab"),
		commandEntry("diagnostic/quic", "diagnostic", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "./internal/carrier/rawquic", "./internal/tunnelv2"),
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		tests = append(tests,
			commandEntry("controller/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectionController"),
			commandEntry("protocol/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "TransportV2|IDNAHostV2"),
			commandEntry("interop/swift-go/wss/direct", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectorV2Tests/testRealGoWSSDirectEndToEnd"),
			commandEntry("interop/swift-go/wss/tunnel", "acceptance", 5*time.Minute, "swift", "test", "--filter", "ConnectorV2Tests/testRealGoWSSTunnelEndToEnd"),
		)
	}
	for _, id := range []string{
		"CAP-DIRECT-WSS-1000", "CAP-DIRECT-QUIC-1000", "CAP-DIRECT-WT-1000",
		"CAP-TUNNEL-WT-WSS-1000", "CAP-TUNNEL-WT-QUIC-1000",
		"CAP-STREAM-WT-DIRECT-100X128", "CAP-STREAM-WT-WSS-100X128", "CAP-STREAM-WT-QUIC-100X128",
		"CAP-WW-1000", "CAP-QQ-1000", "CAP-WQ-1000", "CAP-QW-1000",
	} {
		tests = append(tests, commandEntryWithEnvironment("performance/capacity/"+strings.ToLower(id), "performance", 5*time.Minute,
			[]string{"FLOWERSEC_TEST_CAPACITY_CASE=" + id}, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestFocusedProductionCapacityCase$", "./internal/transporttest/performance"))
	}
	tests = append(tests, commandEntryWithEnvironment("performance/soak", "performance", 10*time.Minute, []string{"FLOWERSEC_TEST_SOAK=1"}, "go", "-C", "flowersec-go", "test", "-timeout=10m", "-count=1", "-run", "^TestFocusedProductionSoakCase$", "./internal/transporttest/performance"))
	return tests
}

func browserSmokeEntry(id, title string) registeredTest {
	return commandEntry(id, "browser-smoke", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "run", "test:browser:chromium", "--", "--grep", exactTitle(title))
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
		return runCommand(ctx, run.Root, environment, command, arguments...)
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
		select {
		case err := <-done:
			return errors.Join(context.Cause(ctx), err, errors.New(output.String()))
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
			return errors.Join(context.Cause(ctx), errors.New("subprocess ignored SIGTERM"), errors.New(output.String()))
		}
	}
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
