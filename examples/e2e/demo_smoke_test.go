package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const demoOrigin = "https://app.redeven.com"

type controlplaneReady struct {
	ControlplaneHTTPURL   string          `json:"controlplane_http_url"`
	TunnelAudience        string          `json:"tunnel_audience"`
	TunnelIssuer          string          `json:"tunnel_issuer"`
	IssuerKeysFile        string          `json:"issuer_keys_file"`
	TunnelListen          string          `json:"tunnel_listen"`
	TunnelWSPath          string          `json:"tunnel_ws_path"`
	ServerEndpointControl json.RawMessage `json:"server_endpoint_control"`
}

type serverEndpointReady struct {
	Status     string `json:"status"`
	EndpointID string `json:"endpoint_id"`
}

type directDemoReady struct {
	WSURL               string `json:"ws_url"`
	ChannelID           string `json:"channel_id"`
	E2EEPskB64u         string `json:"e2ee_psk_b64u"`
	DefaultSuite        int    `json:"default_suite"`
	ChannelInitExpireAt int64  `json:"channel_init_expire_at_unix_s"`
}

type managedProcess struct {
	cancel context.CancelFunc
	cmd    *exec.Cmd
}

func TestGoTunnelDemoClientsAcceptArtifactBootstrap(t *testing.T) {
	examplesRoot := repoExamplesRoot(t)
	tunnelURL := fmt.Sprintf("ws://127.0.0.1:%d/ws", reserveTCPPort(t))

	controlplane, controlplaneProc := startJSONReadyGoProcess[controlplaneReady](
		t,
		examplesRoot,
		"",
		nil,
		"run",
		"./go/controlplane_demo",
		"--listen",
		"127.0.0.1:0",
		"--tunnel-url",
		tunnelURL,
	)
	defer controlplaneProc.stop()

	_, tunnelProc := startJSONReadyGoProcess[map[string]any](
		t,
		examplesRoot,
		"",
		nil,
		"run",
		"../flowersec-go/cmd/flowersec-tunnel",
		"--listen",
		controlplane.TunnelListen,
		"--ws-path",
		controlplane.TunnelWSPath,
		"--issuer-keys-file",
		controlplane.IssuerKeysFile,
		"--aud",
		controlplane.TunnelAudience,
		"--iss",
		controlplane.TunnelIssuer,
		"--allow-origin",
		demoOrigin,
	)
	defer tunnelProc.stop()

	controlplaneJSON, err := json.Marshal(controlplane)
	if err != nil {
		t.Fatalf("marshal controlplane ready: %v", err)
	}
	serverEndpoint, serverEndpointProc := startJSONReadyGoProcess[serverEndpointReady](
		t,
		examplesRoot,
		string(controlplaneJSON)+"\n",
		nil,
		"run",
		"./go/server_endpoint",
		"--origin",
		demoOrigin,
		"--endpoint-id",
		"server-1",
	)
	defer serverEndpointProc.stop()
	if serverEndpoint.Status != "ready" || serverEndpoint.EndpointID != "server-1" {
		t.Fatalf("unexpected server endpoint ready payload: %+v", serverEndpoint)
	}

	simpleOut := runGoCommand(
		t,
		examplesRoot,
		requestTunnelArtifactEnvelope(t, controlplane.ControlplaneHTTPURL, serverEndpoint.EndpointID),
		nil,
		"run",
		"./go/go_client_tunnel_simple",
		"--origin",
		demoOrigin,
	)
	expectDemoOutput(t, simpleOut)

	advancedOut := runGoCommand(
		t,
		examplesRoot,
		requestTunnelArtifactEnvelope(t, controlplane.ControlplaneHTTPURL, serverEndpoint.EndpointID),
		nil,
		"run",
		"./go/go_client_tunnel",
		"--origin",
		demoOrigin,
	)
	expectDemoOutput(t, advancedOut)
}

func TestGoDirectDemoClientsAcceptArtifactBootstrap(t *testing.T) {
	examplesRoot := repoExamplesRoot(t)

	directReady, directProc := startJSONReadyGoProcess[directDemoReady](
		t,
		examplesRoot,
		"",
		nil,
		"run",
		"./go/direct_demo",
		"--allow-origin",
		demoOrigin,
	)
	defer directProc.stop()

	directEnvelope := makeDirectArtifactEnvelope(t, directReady)

	simpleOut := runGoCommand(
		t,
		examplesRoot,
		directEnvelope,
		nil,
		"run",
		"./go/go_client_direct_simple",
		"--origin",
		demoOrigin,
	)
	expectDemoOutput(t, simpleOut)

	advancedOut := runGoCommand(
		t,
		examplesRoot,
		directEnvelope,
		nil,
		"run",
		"./go/go_client_direct",
		"--origin",
		demoOrigin,
	)
	expectDemoOutput(t, advancedOut)
}

func repoExamplesRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, ".."))
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP port: %v", err)
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type: %T", ln.Addr())
	}
	return addr.Port
}

func startJSONReadyGoProcess[T any](t *testing.T, cwd string, stdin string, env []string, args ...string) (T, *managedProcess) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe for %v: %v", args, err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %v: %v", args, err)
	}

	line, err := readLineWithTimeout(stdout, 60*time.Second)
	if err != nil {
		cancel()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		t.Fatalf("wait for ready JSON from %v: %v\nstderr:\n%s", args, err, stderr.String())
	}

	var ready T
	if err := json.Unmarshal([]byte(line), &ready); err != nil {
		cancel()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		t.Fatalf("decode ready JSON from %v: %v\nline: %s\nstderr:\n%s", args, err, line, stderr.String())
	}

	return ready, &managedProcess{cancel: cancel, cmd: cmd}
}

func readLineWithTimeout(r io.Reader, timeout time.Duration) (string, error) {
	reader := bufio.NewReader(r)
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := reader.ReadString('\n')
		done <- result{line: strings.TrimSpace(line), err: err}
	}()

	select {
	case out := <-done:
		if out.err != nil && out.err != io.EOF {
			return "", out.err
		}
		if out.line == "" {
			if out.err == nil {
				return "", io.ErrUnexpectedEOF
			}
			return "", out.err
		}
		return out.line, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("timeout after %s", timeout)
	}
}

func (p *managedProcess) stop() {
	if p == nil || p.cmd == nil {
		return
	}
	p.cancel()
	if p.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		_ = p.cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
}

func runGoCommand(t *testing.T, cwd string, stdin string, env []string, args ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run %v failed: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func requestTunnelArtifactEnvelope(t *testing.T, baseURL string, endpointID string) string {
	t.Helper()

	body := strings.NewReader(fmt.Sprintf(`{"endpoint_id":%q}`, endpointID))
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/connect/artifact", body)
	if err != nil {
		t.Fatalf("new artifact request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request connect artifact: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read connect artifact response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected connect artifact status=%d body=%s", resp.StatusCode, string(raw))
	}
	return string(raw)
}

func makeDirectArtifactEnvelope(t *testing.T, ready directDemoReady) string {
	t.Helper()

	envelope := map[string]any{
		"connect_artifact": map[string]any{
			"v":         1,
			"transport": "direct",
			"direct_info": map[string]any{
				"ws_url":                        ready.WSURL,
				"channel_id":                    ready.ChannelID,
				"e2ee_psk_b64u":                 ready.E2EEPskB64u,
				"channel_init_expire_at_unix_s": ready.ChannelInitExpireAt,
				"default_suite":                 ready.DefaultSuite,
			},
		},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal direct artifact envelope: %v", err)
	}
	return string(raw)
}

func expectDemoOutput(t *testing.T, output string) {
	t.Helper()

	if !strings.Contains(output, `rpc response: {"ok":true}`) {
		t.Fatalf("missing rpc response in output: %s", output)
	}
	if !strings.Contains(output, `rpc notify: {"hello":"world"}`) {
		t.Fatalf("missing rpc notify in output: %s", output)
	}
	if !strings.Contains(output, `echo response: "hello over yamux stream: echo"`) {
		t.Fatalf("missing echo response in output: %s", output)
	}
}
