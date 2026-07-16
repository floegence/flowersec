package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/interopprotocol"
	"github.com/gorilla/websocket"
)

func prepareHarnesses(repoRoot string, cells []string) error {
	commands := make([]*exec.Cmd, 0, 3)
	if slices.Contains(cells, "typescript_to_go") || slices.Contains(cells, "go_to_typescript") {
		command := exec.Command("npm", "run", "build")
		command.Dir = filepath.Join(repoRoot, "flowersec-ts")
		commands = append(commands, command)
	}
	if slices.Contains(cells, "rust_to_go") || slices.Contains(cells, "go_to_rust") {
		command := exec.Command("cargo", "build", "--all-features", "--example", "interop_harness")
		command.Dir = filepath.Join(repoRoot, "flowersec-rust")
		commands = append(commands, command)
	}
	if slices.Contains(cells, "swift_to_go") || slices.Contains(cells, "go_to_swift") {
		command := exec.Command("swift", "build", "--product", "FlowersecInteropHarness")
		command.Dir = repoRoot
		commands = append(commands, command)
	}
	for _, command := range commands {
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("prepare interop harness with %q: %w\n%s", command.Args, err, output)
		}
	}
	return nil
}

func (e *environment) runExternalCell(
	ctx context.Context,
	repoRoot string,
	cell string,
	profile string,
	value variant,
	workload interopprotocol.Workload,
) (timedResult, error) {
	started := time.Now()
	parts := strings.Split(cell, "_to_")
	if len(parts) != 2 {
		return timedResult{}, fmt.Errorf("invalid matrix cell %q", cell)
	}
	var metrics interopprotocol.Metrics
	diagnostics := make([]interopprotocol.Diagnostic, 0, workload.LimitChecks)
	var err error
	if parts[1] == "go" {
		metrics, err = e.runExternalClient(ctx, repoRoot, parts[0], cell, profile, value, workload, &diagnostics)
	} else if parts[0] == "go" {
		metrics, err = e.runExternalServer(ctx, repoRoot, parts[1], cell, profile, value, workload, &diagnostics)
	} else {
		err = fmt.Errorf("non-Go pairwise cell %q is forbidden", cell)
	}
	return timedResult{Metrics: metrics, Diagnostics: diagnostics, Duration: time.Since(started)}, err
}

func (e *environment) runExternalClient(
	ctx context.Context,
	repoRoot, language, cell, profile string,
	value variant,
	workload interopprotocol.Workload,
	diagnostics *[]interopprotocol.Diagnostic,
) (interopprotocol.Metrics, error) {
	requestID := strings.Join([]string{cell, value.Transport, value.Suite}, "-")
	command := interopprotocol.Command{
		V: interopprotocol.Version, Event: "run_client", RequestID: requestID,
		Profile: profile, Transport: value.Transport, Suite: value.Suite,
		DeadlineMS: remainingMilliseconds(ctx), Origin: interopOrigin,
		UpstreamURL: e.upstream.URL, Workload: workload,
		LimitArtifacts: []interopprotocol.LimitArtifact{},
	}
	reconnectPeers, reconnectArtifacts, err := e.startGoPeerFleet(ctx, value, workload)
	if err != nil {
		return interopprotocol.Metrics{}, err
	}
	command.ReconnectArtifacts = reconnectArtifacts
	limitPeers, limitArtifacts, err := e.startGoLimitFleet(ctx, value, workload)
	if err != nil {
		return interopprotocol.Metrics{}, errors.Join(err, abortGoPeerFleet(ctx, reconnectPeers))
	}
	command.LimitArtifacts = limitArtifacts
	serverCtx, cancelServer := context.WithCancel(ctx)
	defer cancelServer()
	serverDone := make(chan error, 1)
	var closeDirect func()
	if value.Transport == "direct" {
		credential, info, err := e.directCredential(value.Suite)
		if err != nil {
			return interopprotocol.Metrics{}, err
		}
		upgrader := websocket.Upgrader{CheckOrigin: func(request *http.Request) bool {
			return request.Header.Get("Origin") == interopOrigin
		}}
		directServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
			if upgradeErr != nil {
				serverDone <- upgradeErr
				return
			}
			defer connection.Close()
			session, acceptErr := endpoint.AcceptDirectWS(serverCtx, connection, endpoint.AcceptDirectOptions{
				ChannelID: credential.ChannelID, Suite: endpoint.Suite(credential.Suite),
				PSK: mustDecodePSK(credential.PSK), InitExpireAtUnixS: credential.InitExpiresAtUnix,
				ClockSkew:   30 * time.Second,
				YamuxLimits: serverYamuxLimits(workload),
			})
			if acceptErr != nil {
				serverDone <- acceptErr
				return
			}
			serverDone <- e.serveReferenceSession(serverCtx, session, workload)
		}))
		closeDirect = directServer.Close
		info.WsUrl = "ws" + strings.TrimPrefix(directServer.URL, "http")
		command.DirectInfo = info
	} else {
		clientGrant, serverGrant, err := e.grants(value.Suite)
		if err != nil {
			return interopprotocol.Metrics{}, err
		}
		command.TunnelGrant = clientGrant
		go func() {
			session, connectErr := endpoint.ConnectTunnel(serverCtx, serverGrant,
				endpoint.WithOrigin(interopOrigin),
				endpoint.WithTransportSecurityPolicy(endpoint.AllowPlaintextForLoopback),
				endpoint.WithLivenessDisabled(),
				endpoint.WithYamuxLimits(serverYamuxLimits(workload)),
			)
			if connectErr != nil {
				serverDone <- connectErr
				return
			}
			serverDone <- e.serveReferenceSession(serverCtx, session, workload)
		}()
	}
	if closeDirect != nil {
		defer closeDirect()
	}
	result, runErr := runHarnessClient(ctx, repoRoot, language, command)
	*diagnostics = append(*diagnostics, result.Diagnostics...)
	cancelServer()
	serverErr := waitServer(serverDone, ctx)
	if runErr != nil {
		return result.Metrics, errors.Join(
			runErr,
			serverErr,
			abortGoPeerFleet(ctx, reconnectPeers),
			abortGoPeerFleet(ctx, limitPeers),
		)
	}
	reconnectErr := waitGoPeerFleet(ctx, reconnectPeers)
	limitErr := waitGoPeerFleet(ctx, limitPeers)
	if err := validateClientMetrics(result.Metrics, workload); err != nil {
		return result.Metrics, errors.Join(err, serverErr, reconnectErr, limitErr)
	}
	return result.Metrics, errors.Join(serverErr, reconnectErr, limitErr)
}

func (e *environment) runExternalServer(
	ctx context.Context,
	repoRoot, language, cell, profile string,
	value variant,
	workload interopprotocol.Workload,
	diagnostics *[]interopprotocol.Diagnostic,
) (interopprotocol.Metrics, error) {
	requestID := strings.Join([]string{cell, value.Transport, value.Suite}, "-")
	command := interopprotocol.Command{
		V: interopprotocol.Version, Event: "serve", RequestID: requestID,
		Profile: profile, Transport: value.Transport, Suite: value.Suite,
		DeadlineMS: remainingMilliseconds(ctx), Origin: interopOrigin,
		UpstreamURL: e.upstream.URL, Workload: workload,
		ReconnectArtifacts: []interopprotocol.ClientArtifact{},
		LimitArtifacts:     []interopprotocol.LimitArtifact{},
	}
	var clientGrant *controlv1.ChannelInitGrant
	if value.Transport == "direct" {
		credential, _, err := e.directCredential(value.Suite)
		if err != nil {
			return interopprotocol.Metrics{}, err
		}
		command.DirectCredential = &credential
	} else {
		clientValue, serverValue, err := e.grants(value.Suite)
		if err != nil {
			return interopprotocol.Metrics{}, err
		}
		clientGrant = clientValue
		command.TunnelGrant = serverValue
	}
	harness, ready, err := startHarnessServer(ctx, repoRoot, language, command)
	if err != nil {
		return interopprotocol.Metrics{}, err
	}
	var connected client.Client
	if value.Transport == "direct" {
		if ready.DirectInfo == nil {
			return interopprotocol.Metrics{}, errors.Join(errors.New("server harness omitted direct_info"), harness.abort())
		}
		connected, err = client.ConnectDirect(ctx, ready.DirectInfo,
			client.WithOrigin(interopOrigin),
			client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
			client.WithLivenessDisabled(),
		)
	} else {
		connected, err = client.ConnectTunnel(ctx, clientGrant,
			client.WithOrigin(interopOrigin),
			client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
			client.WithLivenessDisabled(),
		)
	}
	if err != nil {
		return interopprotocol.Metrics{}, errors.Join(err, harness.abort())
	}
	metrics, exerciseErr := exerciseGoClient(ctx, connected, e.upstream.URL, workload, diagnostics)
	closeErr := connected.Close()
	serverResult, stopErr := harness.stop(requestID)
	if stopErr == nil && len(serverResult.Diagnostics) != 0 {
		stopErr = errors.New("server harness returned unexpected diagnostics")
	}
	if err := errors.Join(exerciseErr, closeErr, stopErr); err != nil {
		return metrics, err
	}
	reconnectMetrics, reconnectErr := e.runGoReconnectAgainstHarness(
		ctx, repoRoot, language, cell, profile, value, workload,
	)
	metrics.Sessions += reconnectMetrics.Sessions
	metrics.Reconnects += reconnectMetrics.Reconnects
	if reconnectErr != nil {
		return metrics, reconnectErr
	}
	limitMetrics, limitErr := e.runGoLimitsAgainstHarness(
		ctx, repoRoot, language, cell, profile, value, workload, diagnostics,
	)
	mergeLimitMetrics(&metrics, limitMetrics)
	if err := validateClientMetrics(metrics, workload); err != nil {
		return metrics, errors.Join(err, limitErr)
	}
	return metrics, limitErr
}

type harnessProcess struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	stderr  *bytes.Buffer
	waited  bool
	state   harnessProcessState
}

type harnessProcessState string

const (
	harnessStateHello   harnessProcessState = "hello"
	harnessStateReady   harnessProcessState = "ready"
	harnessStateResult  harnessProcessState = "result"
	harnessStateFatal   harnessProcessState = "fatal"
	harnessStateAborted harnessProcessState = "aborted"
)

func runHarnessClient(ctx context.Context, repoRoot, language string, command interopprotocol.Command) (interopprotocol.Result, error) {
	process, err := startHarness(ctx, repoRoot, language)
	if err != nil {
		return interopprotocol.Result{}, err
	}
	if err := interopprotocol.Encode(process.stdin, command); err != nil {
		return interopprotocol.Result{}, errors.Join(err, process.abort())
	}
	result, err := process.readResult(command.RequestID)
	if err != nil {
		return result, errors.Join(err, process.abort())
	}
	return result, errors.Join(process.stdin.Close(), process.wait())
}

func startHarnessServer(ctx context.Context, repoRoot, language string, command interopprotocol.Command) (*harnessProcess, interopprotocol.Ready, error) {
	process, err := startHarness(ctx, repoRoot, language)
	if err != nil {
		return nil, interopprotocol.Ready{}, err
	}
	if err := interopprotocol.Encode(process.stdin, command); err != nil {
		return nil, interopprotocol.Ready{}, errors.Join(err, process.abort())
	}
	ready, err := process.readReady(command.RequestID)
	if err != nil {
		return nil, interopprotocol.Ready{}, errors.Join(err, process.abort())
	}
	return process, ready, nil
}

func startHarness(ctx context.Context, repoRoot, language string) (*harnessProcess, error) {
	command, err := harnessCommand(ctx, repoRoot, language)
	if err != nil {
		return nil, err
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.Join(err, stdin.Close())
	}
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, errors.Join(err, stdin.Close(), stdoutPipe.Close())
	}
	process := &harnessProcess{command: command, stdin: stdin, stdout: bufio.NewReader(stdoutPipe), stderr: stderr}
	line, err := process.readLine()
	if err != nil {
		return nil, errors.Join(err, process.abort())
	}
	var hello interopprotocol.Hello
	if err := decodeStrictLine(line, &hello); err != nil {
		return nil, errors.Join(err, process.abort())
	}
	if err := interopprotocol.ValidateHello(hello, language); err != nil {
		return nil, errors.Join(err, process.abort())
	}
	process.state = harnessStateHello
	return process, nil
}

func harnessCommand(ctx context.Context, repoRoot, language string) (*exec.Cmd, error) {
	var command *exec.Cmd
	switch language {
	case "typescript":
		command = exec.CommandContext(ctx, "node", filepath.Join(repoRoot, "flowersec-ts/scripts/interop-harness.mjs"))
		command.Dir = filepath.Join(repoRoot, "flowersec-ts")
	case "rust":
		command = exec.CommandContext(ctx, filepath.Join(repoRoot, "flowersec-rust/target/debug/examples/interop_harness"), "--protocol")
		command.Dir = filepath.Join(repoRoot, "flowersec-rust")
	case "swift":
		command = exec.CommandContext(ctx, filepath.Join(repoRoot, ".build/debug/FlowersecInteropHarness"), "--protocol")
		command.Dir = repoRoot
	default:
		return nil, fmt.Errorf("unsupported harness language %q", language)
	}
	return command, nil
}

func (p *harnessProcess) readReady(requestID string) (interopprotocol.Ready, error) {
	if p.state != harnessStateHello {
		return interopprotocol.Ready{}, fmt.Errorf("harness ready event is invalid in state %q", p.state)
	}
	line, err := p.readLine()
	if err != nil {
		return interopprotocol.Ready{}, err
	}
	event, err := peekEvent(line)
	if err != nil {
		return interopprotocol.Ready{}, err
	}
	if event == "fatal" {
		p.state = harnessStateFatal
		return interopprotocol.Ready{}, fmt.Errorf("%w; stderr=%s", decodeFatal(line), p.stderr.String())
	}
	var ready interopprotocol.Ready
	if err := decodeStrictLine(line, &ready); err != nil {
		return interopprotocol.Ready{}, err
	}
	if ready.V != interopprotocol.Version || ready.Event != "ready" || ready.RequestID != requestID {
		return interopprotocol.Ready{}, errors.New("invalid harness ready event")
	}
	p.state = harnessStateReady
	return ready, nil
}

func (p *harnessProcess) readResult(requestID string) (interopprotocol.Result, error) {
	if p.state != harnessStateHello && p.state != harnessStateReady {
		return interopprotocol.Result{}, fmt.Errorf("harness result event is invalid in state %q", p.state)
	}
	line, err := p.readLine()
	if err != nil {
		return interopprotocol.Result{}, err
	}
	event, err := peekEvent(line)
	if err != nil {
		return interopprotocol.Result{}, err
	}
	if event == "fatal" {
		p.state = harnessStateFatal
		return interopprotocol.Result{}, fmt.Errorf("%w; stderr=%s", decodeFatal(line), p.stderr.String())
	}
	var result interopprotocol.Result
	if err := decodeStrictLine(line, &result); err != nil {
		return interopprotocol.Result{}, err
	}
	if result.V != interopprotocol.Version || result.Event != "result" || result.RequestID != requestID {
		return result, errors.New("invalid harness result event")
	}
	p.state = harnessStateResult
	return result, nil
}

func (p *harnessProcess) stop(requestID string) (interopprotocol.Result, error) {
	if p.state != harnessStateReady {
		return interopprotocol.Result{}, fmt.Errorf("harness stop is invalid in state %q", p.state)
	}
	if err := interopprotocol.Encode(p.stdin, interopprotocol.Stop{V: interopprotocol.Version, Event: "stop", RequestID: requestID}); err != nil {
		return interopprotocol.Result{}, errors.Join(err, p.abort())
	}
	result, err := p.readResult(requestID)
	if err != nil {
		return result, errors.Join(err, p.abort())
	}
	return result, errors.Join(p.stdin.Close(), p.wait())
}

func (p *harnessProcess) readLine() ([]byte, error) {
	line, err := p.stdout.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("harness stdout ended before a complete event: %w; stderr=%s", err, p.stderr.String())
	}
	return bytes.TrimSpace(line), nil
}

func (p *harnessProcess) wait() error {
	if p.waited {
		return errors.New("harness process was waited more than once")
	}
	if p.state != harnessStateResult {
		return fmt.Errorf("harness wait is invalid in state %q", p.state)
	}
	p.waited = true
	if err := p.command.Wait(); err != nil {
		return fmt.Errorf("harness exited unsuccessfully: %w; stderr=%s", err, p.stderr.String())
	}
	return nil
}

func (p *harnessProcess) abort() error {
	if p == nil || p.waited {
		return nil
	}
	p.waited = true
	p.state = harnessStateAborted
	closeErr := p.stdin.Close()
	killErr := p.command.Process.Kill()
	waitErr := p.command.Wait()
	if errors.Is(killErr, exec.ErrNotFound) || errors.Is(killErr, os.ErrProcessDone) {
		killErr = nil
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		waitErr = nil
	}
	return errors.Join(
		errors.New("harness process was forcibly terminated"),
		closeErr,
		killErr,
		waitErr,
		p.stderrError(),
	)
}

func (p *harnessProcess) stderrError() error {
	message := strings.TrimSpace(p.stderr.String())
	if message == "" {
		return nil
	}
	return fmt.Errorf("harness stderr: %s", message)
}

func decodeStrictLine(line []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("harness event contains trailing JSON")
		}
		return err
	}
	return nil
}

func peekEvent(line []byte) (string, error) {
	var value struct {
		Event string `json:"event"`
	}
	if err := json.Unmarshal(line, &value); err != nil {
		return "", err
	}
	if value.Event == "" {
		return "", errors.New("harness event is missing event")
	}
	return value.Event, nil
}

func decodeFatal(line []byte) error {
	var fatal interopprotocol.Fatal
	if err := decodeStrictLine(line, &fatal); err != nil {
		return err
	}
	return fmt.Errorf("harness fatal %s/%s: %s", fatal.Stage, fatal.Code, fatal.Message)
}

func remainingMilliseconds(ctx context.Context) int {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 1
	}
	remaining := time.Until(deadline).Milliseconds()
	if remaining < 1 {
		return 1
	}
	return int(remaining)
}

func validateClientMetrics(metrics interopprotocol.Metrics, workload interopprotocol.Workload) error {
	minimumStreams := workload.Streams.Concurrent + workload.Streams.Churn + workload.Streams.FIN + workload.Streams.Reset
	minimumRekeys := workload.Rekey.Client + workload.Rekey.Server + 2*workload.Rekey.Concurrent
	expectedSessions := workload.ReconnectCycles + 2 + max(0, workload.LimitChecks-1)
	if metrics.Sessions != expectedSessions || metrics.Streams < minimumStreams || metrics.Resets < workload.Streams.Reset {
		return fmt.Errorf("client stream metrics are incomplete: %+v", metrics)
	}
	if metrics.SlowReaders != workload.Streams.SlowReaders || metrics.FINs != workload.Streams.FIN {
		return fmt.Errorf("client FIN/backpressure metrics are incomplete: %+v", metrics)
	}
	if metrics.Rekeys < minimumRekeys || metrics.LivenessProbes < workload.LivenessProbes {
		return fmt.Errorf("client security/liveness metrics are incomplete: %+v", metrics)
	}
	if metrics.Reconnects != workload.ReconnectCycles {
		return fmt.Errorf("client reconnect metrics are incomplete: %+v", metrics)
	}
	if metrics.RPCCalls < workload.RPC.Calls || metrics.RPCNotifications < workload.RPC.Notifications ||
		metrics.RPCCancellations < workload.RPC.Cancellations || metrics.RPCTimeouts < workload.RPC.Timeouts ||
		metrics.RPCQueueRejections != workload.RPC.SaturationRejected {
		return fmt.Errorf("client RPC metrics are incomplete: %+v", metrics)
	}
	if metrics.LimitChecks != workload.LimitChecks ||
		metrics.ResourceRejections+metrics.BackpressureChecks != workload.LimitChecks {
		return fmt.Errorf("client resource-limit metrics are incomplete: %+v", metrics)
	}
	if metrics.HTTPRequests < workload.Proxy.HTTPRequests || metrics.WebSocketFrames < workload.Proxy.WebSocketFrames {
		return fmt.Errorf("client proxy metrics are incomplete: %+v", metrics)
	}
	return nil
}
