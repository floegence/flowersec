package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest/acceptance"
)

func registry() []registeredTest {
	tests := []registeredTest{
		commandEntry("protocol/go", "acceptance", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "./internal/protocolv2", "./internal/artifactv2", "./internal/admissionv2", "./internal/session"),
		commandEntry("protocol/typescript", "acceptance", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "test", "--", "--run", "src/v2"),
		commandEntry("protocol/ts-node-webtransport", "acceptance", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "exec", "--", "vitest", "run", "src/node/webTransport.integration.test.ts"),
		commandEntry("protocol/rust", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "--test", "transport_v2_contract"),
		commandEntry("protocol/interop-typescript-go", "acceptance", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "exec", "--", "vitest", "run", "src/interop/goSession.integration.test.ts"),
		commandEntry("protocol/interop-rust-go", "acceptance", 5*time.Minute, "rustup", "run", "1.88.0", "cargo", "test", "--manifest-path", "flowersec-rust/Cargo.toml", "--all-features", "--lib", "rust_and_go_run_full_session_v2_over_raw_quic_direct_and_tunnel"),
		browserSmokeEntry("browser/chromium-direct", acceptance.BrowserDirectTopology),
		browserSmokeEntry("browser/chromium-tunnel-wt-wss", acceptance.BrowserTunnelWTWSS),
		browserSmokeEntry("browser/chromium-tunnel-wt-quic", acceptance.BrowserTunnelWTQUIC),
		commandEntry("diagnostic/protocol", "diagnostic", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "./internal/protocolv2", "./internal/artifactv2", "./internal/admissionv2", "./internal/session", "./internal/transporttest"),
		commandEntry("diagnostic/browser", "diagnostic", 10*time.Minute, "npm", "--prefix", "flowersec-ts", "run", "test:browser"),
		commandEntry("diagnostic/interop", "diagnostic", 5*time.Minute, "npm", "--prefix", "flowersec-ts", "exec", "--", "vitest", "run", "src/interop/goSession.integration.test.ts"),
		commandEntryWithEnvironment("diagnostic/weaknet", "diagnostic", 5*time.Minute, []string{"FLOWERSEC_RUN_WEAKNET_SMOKE=1"}, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "./internal/weaknet", "./internal/weaknetsmoke"),
		commandEntryWithEnvironment("diagnostic/kernel-outage", "diagnostic", 5*time.Minute, []string{"FLOWERSEC_LINUX_NETLAB_INTEGRATION=1"}, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "-run", "^TestPrivilegedReorderDuplicateAndOutage$", "./internal/transporttest/linuxnetlab"),
		commandEntry("diagnostic/quic", "diagnostic", 5*time.Minute, "go", "-C", "flowersec-go", "test", "-timeout=5m", "-count=1", "./internal/carrier/rawquic", "./internal/tunnelv2"),
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		tests = append(tests, commandEntry("protocol/swift", "acceptance", 5*time.Minute, "swift", "test", "--filter", "TransportV2|IDNAHostV2"))
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

func browserSmokeEntry(id, topology string) registeredTest {
	return registeredTest{ID: id, Suite: "browser-smoke", Timeout: 10 * time.Minute, Run: func(ctx context.Context, run runContext) error {
		return acceptance.RunTest(ctx, acceptance.RunContext{RunID: run.RunID, TempDir: run.TempDir, Root: run.Root, Debug: run.Debug}, topology)
	}}
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
