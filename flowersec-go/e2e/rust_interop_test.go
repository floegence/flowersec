package e2e_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	demov1 "github.com/floegence/flowersec/flowersec-go/internal/testgen/flowersec/demo/v1"
	"github.com/floegence/flowersec/flowersec-go/proxy"
)

type rustHarnessReady struct {
	V          int                        `json:"v"`
	Event      string                     `json:"event"`
	DirectInfo directv1.DirectConnectInfo `json:"direct_info"`
}

type goExternalReady struct {
	GrantClient *controlv1.ChannelInitGrant `json:"grant_client"`
	GrantServer *controlv1.ChannelInitGrant `json:"grant_server"`
}

func TestGoClientInteroperatesWithRustEndpointRPCStreamLivenessAndProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, rustInteropBinary(t, ctx))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("read Rust harness readiness: %v", scanner.Err())
	}
	var ready rustHarnessReady
	if err := json.Unmarshal(scanner.Bytes(), &ready); err != nil {
		t.Fatal(err)
	}
	if ready.V != 1 || ready.Event != "ready" {
		t.Fatalf("unexpected Rust harness readiness: %+v", ready)
	}

	cli, err := client.ConnectDirect(
		ctx,
		&ready.DirectInfo,
		client.WithOrigin("https://app.example.com"),
		client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
		client.WithLivenessDisabled(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	exerciseGoClientAgainstRust(t, ctx, cli)
}

func TestGoClientInteroperatesWithRustEndpointThroughTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	goHarness := exec.CommandContext(ctx, goInteropBinary(t, ctx), "-external-server")
	goStdout, err := goHarness.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	goHarness.Stderr = os.Stderr
	if err := goHarness.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if goHarness.Process != nil {
			_ = goHarness.Process.Kill()
		}
		_ = goHarness.Wait()
	})
	goScanner := bufio.NewScanner(goStdout)
	if !goScanner.Scan() {
		t.Fatalf("read Go harness readiness: %v", goScanner.Err())
	}
	var grants goExternalReady
	if err := json.Unmarshal(goScanner.Bytes(), &grants); err != nil {
		t.Fatal(err)
	}
	if grants.GrantClient == nil || grants.GrantServer == nil {
		t.Fatal("Go harness did not return both grants")
	}
	serverGrant, err := json.Marshal(grants.GrantServer)
	if err != nil {
		t.Fatal(err)
	}

	rustHarness := exec.CommandContext(
		ctx,
		rustInteropBinary(t, ctx),
		"--tunnel-grant-json",
		string(serverGrant),
	)
	rustStdout, err := rustHarness.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	rustHarness.Stderr = os.Stderr
	if err := rustHarness.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if rustHarness.Process != nil {
			_ = rustHarness.Process.Kill()
		}
		_ = rustHarness.Wait()
	})
	rustScanner := bufio.NewScanner(rustStdout)
	if !rustScanner.Scan() {
		t.Fatalf("read Rust attaching event: %v", rustScanner.Err())
	}
	var event struct {
		V     int    `json:"v"`
		Event string `json:"event"`
	}
	if err := json.Unmarshal(rustScanner.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.V != 1 || event.Event != "attaching" {
		t.Fatalf("unexpected Rust harness event: %+v", event)
	}

	cli, err := client.ConnectTunnel(
		ctx,
		grants.GrantClient,
		client.WithOrigin("https://app.redeven.com"),
		client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
		client.WithLivenessDisabled(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	exerciseGoClientAgainstRust(t, ctx, cli)
}

func rustInteropBinary(t *testing.T, ctx context.Context) string {
	t.Helper()
	rustDir, err := filepath.Abs(filepath.Join("..", "..", "flowersec-rust"))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "cargo", "build", "--quiet", "--example", "interop_harness")
	build.Dir = rustDir
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(rustDir, "target", "debug", "examples", "interop_harness")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	return binary
}

func goInteropBinary(t *testing.T, ctx context.Context) string {
	t.Helper()
	goDir, err := filepath.Abs(filepath.Join(".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "flowersec-e2e-harness")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./internal/cmd/flowersec-e2e-harness")
	build.Dir = goDir
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}
	return binary
}

func exerciseGoClientAgainstRust(t *testing.T, ctx context.Context, cli client.Client) {
	t.Helper()

	demo := demov1.NewDemoClient(cli.RPC())
	notify := make(chan *demov1.HelloNotify, 1)
	unsubscribe := demo.OnHello(func(message *demov1.HelloNotify) { notify <- message })
	defer unsubscribe()
	response, err := demo.Ping(ctx, &demov1.PingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !response.Ok {
		t.Fatal("Rust RPC response was not ok")
	}
	select {
	case message := <-notify:
		if message.Hello != "world" {
			t.Fatalf("unexpected Rust notification: %+v", message)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	echo, err := cli.OpenStream(ctx, "echo")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("go-rust-stream")
	if _, err := echo.Write(payload); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(echo, echoed); err != nil {
		t.Fatal(err)
	}
	if string(echoed) != string(payload) {
		t.Fatalf("unexpected echo: %q", echoed)
	}
	_ = echo.Close()
	if _, err := cli.ProbeLiveness(ctx); err != nil {
		t.Fatal(err)
	}

	proxyClient, err := proxy.NewClient(proxy.ContractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	httpResponse, err := proxyClient.Do(ctx, cli, proxy.ClientHTTPRequest{
		Method: http.MethodGet,
		Path:   "/http",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK || string(body) != "flowersec-rust-proxy-ok" {
		t.Fatalf("unexpected Rust proxy response: status=%d body=%q", httpResponse.StatusCode, body)
	}

	websocket, err := proxyClient.OpenWebSocket(ctx, cli, "/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	websocketPayload := []byte("go-rust-websocket")
	if err := websocket.WriteFrame(1, websocketPayload); err != nil {
		t.Fatal(err)
	}
	op, received, err := websocket.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if op != 1 || string(received) != string(websocketPayload) {
		t.Fatalf("unexpected Rust WebSocket echo: op=%d payload=%q", op, received)
	}
	if err := websocket.Close(); err != nil {
		t.Fatal(err)
	}
}
