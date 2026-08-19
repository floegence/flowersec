//go:build linux

package flowersecweaknet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
	flowersession "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest/linuxnetlab"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest/tunnelworkload"
	"golang.org/x/sys/unix"
)

type weaknetScenario struct {
	profile                 linuxnetlab.FaultProfile
	payloadBytes            int
	expectOutage            bool
	minimumTransferDuration time.Duration
	pathMTU                 int
}

func runPrivilegedFlowersecWeaknet(t interface {
	Helper()
	TempDir() string
}, carrierName, path, scenarioName string) (resultErr error) {
	t.Helper()
	kind, err := parseCarrier(carrierName)
	if err != nil {
		return err
	}
	scenario, err := scenarioFor(scenarioName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	object, err := linuxnetlab.CompileDiagnosticBPFObject(ctx, t.TempDir())
	if err != nil {
		return err
	}
	scenario.profile.BPFObject = object
	var config linuxnetlab.Config
	if scenario.pathMTU > 0 {
		config, err = linuxnetlab.ConfigForRoutedSystemCase("fw"+shortCarrier(carrierName)+shortScenario(scenarioName), os.Getpid()%9999+1, scenario.profile.LinkMTU, linuxnetlab.FrozenFirewall, false)
	} else {
		config, err = linuxnetlab.ConfigForCell("fw"+shortCarrier(carrierName)+shortScenario(scenarioName), os.Getpid()%9999+1, scenario.profile.LinkMTU, linuxnetlab.FrozenFirewall)
	}
	if err != nil {
		return err
	}
	lab, err := linuxnetlab.Open(ctx, linuxnetlab.ExecRunner{}, config)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		resultErr = errors.Join(resultErr, lab.Close(cleanupCtx))
		cleanupCancel()
	}()
	if err := lab.ApplyFaultProfile(ctx, scenario.profile); err != nil {
		return err
	}
	if err := linuxnetlab.ResetFaultObservation(ctx, config.ClientNamespace, config.ServerNamespace); err != nil {
		return err
	}
	if path == "direct" {
		err = runDirect(ctx, carrierName, config, scenarioName)
	} else if path == "tunnel" && scenarioName == "representative" {
		err = runTunnel(ctx, kind, config)
	} else {
		return errors.New("Flowersec weak-network path and scenario are unsupported")
	}
	if err != nil {
		return err
	}
	observation, err := lab.FaultObservation(ctx)
	if err != nil {
		return err
	}
	return validateObservation(scenarioName, observation)
}

func parseCarrier(name string) (carrier.Kind, error) {
	switch name {
	case "websocket":
		return carrier.KindWebSocket, nil
	case "raw-quic":
		return carrier.KindRawQUIC, nil
	default:
		return "", errors.New("Flowersec weak-network carrier must be websocket or raw-quic")
	}
}

func shortCarrier(name string) string {
	if name == "websocket" {
		return "w"
	}
	return "q"
}

func shortScenario(name string) string {
	values := map[string]string{
		"delay-jitter": "dj", "periodic-loss": "pl", "burst-loss": "bl", "outage": "ot",
		"outage-reconnect": "or", "pin-rotation-refresh-backoff-lease": "pr", "reorder": "ro",
		"mtu-large-payload": "mt", "rate-5mbps": "r5", "rate-1mbps": "r1", "reorder-duplicate": "rd", "representative": "rp",
	}
	return values[name]
}

func scenarioFor(name string) (weaknetScenario, error) {
	profile := linuxnetlab.FaultProfile{
		BaseDelay: 60 * time.Millisecond,
		Jitter:    []time.Duration{0, 8 * time.Millisecond, -4 * time.Millisecond, 12 * time.Millisecond, -8 * time.Millisecond, 4 * time.Millisecond, -2 * time.Millisecond, 6 * time.Millisecond},
		LossMode:  linuxnetlab.LossPeriodic, EveryNth: 500,
		RateBitsPerSecond: 5_000_000, TokenBurstBytes: 32_768, QueueBytes: 262_144, LinkMTU: 1280,
	}
	scenario := weaknetScenario{profile: profile, payloadBytes: 256 << 10}
	switch name {
	case "delay-jitter":
		profile.EveryNth = 100_000
	case "reorder":
		profile.EveryNth, profile.ReorderPercent, profile.DuplicatePercent, profile.ReorderDelay = 100_000, 1, 0, 250*time.Millisecond
	case "periodic-loss":
		profile.EveryNth = 50
	case "burst-loss":
		profile.LossMode, profile.EveryNth = linuxnetlab.LossBurst, 0
		profile.BlockSize, profile.BurstFirst, profile.BurstLast = 100, 41, 45
	case "outage":
		profile.EveryNth, profile.OutageStart, profile.OutageDuration = 100_000, time.Second, 2*time.Second
		scenario.expectOutage = true
	case "outage-reconnect":
		profile.EveryNth, profile.OutageStart, profile.OutageDuration = 100_000, time.Second, 2*time.Second
		scenario.expectOutage = true
	case "pin-rotation-refresh-backoff-lease":
		profile.EveryNth = 100_000
	case "mtu-large-payload":
		profile.LinkMTU = 1500
		scenario.payloadBytes = 2 << 20
		scenario.pathMTU = 1280
	case "rate-5mbps":
		profile.EveryNth = 100_000
		scenario.minimumTransferDuration = shapedTransferMinimum(profile.RateBitsPerSecond, profile.TokenBurstBytes, scenario.payloadBytes)
	case "rate-1mbps":
		profile.EveryNth, profile.RateBitsPerSecond, profile.TokenBurstBytes, profile.QueueBytes = 100_000, 1_000_000, 16_384, 65_536
		scenario.minimumTransferDuration = shapedTransferMinimum(profile.RateBitsPerSecond, profile.TokenBurstBytes, scenario.payloadBytes)
	case "reorder-duplicate":
		profile.EveryNth, profile.ReorderPercent, profile.DuplicatePercent, profile.ReorderDelay = 100_000, 1, 1, 250*time.Millisecond
	case "representative":
		profile.EveryNth = 100
	default:
		return weaknetScenario{}, errors.New("unknown Flowersec weak-network scenario")
	}
	scenario.profile = profile
	return scenario, nil
}

func shapedTransferMinimum(rateBitsPerSecond, tokenBurstBytes, payloadBytes int) time.Duration {
	if rateBitsPerSecond <= 0 || tokenBurstBytes < 0 || payloadBytes <= 0 {
		return 0
	}
	deficit := payloadBytes - tokenBurstBytes
	if deficit < 0 {
		deficit = 0
	}
	return time.Duration(float64(deficit*8) / float64(rateBitsPerSecond) * float64(time.Second) * 0.90)
}

type pathMTUProbe func(context.Context, string, string) (int, error)

func verifyPathMTU(ctx context.Context, namespace, destination string, expected int, probe pathMTUProbe) error {
	if probe == nil || expected < 1280 {
		return errors.New("Flowersec PMTU verification contract is invalid")
	}
	mtu, err := probe(ctx, namespace, destination)
	if err != nil {
		return fmt.Errorf("Flowersec workload did not learn PMTU %d after transfer: %w", expected, err)
	}
	if mtu != expected {
		return fmt.Errorf("Flowersec workload did not learn PMTU %d after transfer: mtu=%d", expected, mtu)
	}
	return nil
}

func socketScopedPathMTU(ctx context.Context, namespace, destination string) (int, error) {
	if err := linuxnetlab.RequireCurrentNamespace(namespace); err != nil {
		return 0, err
	}
	address, err := netip.ParseAddr(destination)
	if err != nil || !address.Is4() {
		return 0, errors.New("Flowersec PMTU probe requires an IPv4 destination")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
		return 0, err
	}
	bytes := address.As4()
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: 9, Addr: bytes}); err != nil {
		return 0, err
	}
	probe := make([]byte, 1400)
	for {
		_ = unix.Send(fd, probe, 0)
		mtu, mtuErr := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU)
		if mtuErr != nil {
			return 0, mtuErr
		}
		if mtu < 1500 {
			return mtu, nil
		}
		select {
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func runDirect(ctx context.Context, carrierName string, config linuxnetlab.Config, scenarioName string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "nsenter", "--net=/var/run/netns/"+config.ClientNamespace, "--", executable, "-test.run=^TestPrivilegedFlowersecWeaknet$", "-test.count=1")
	command.Env = append(os.Environ(),
		"FLOWERSEC_LINUX_NETLAB_INTEGRATION=1",
		"FLOWERSEC_REQUIRED_DIAGNOSTIC=1",
		"FLOWERSEC_WEAKNET_DIRECT_WORKER=1",
		"FLOWERSEC_WEAKNET_CARRIER="+carrierName,
		"FLOWERSEC_WEAKNET_SCENARIO="+scenarioName,
		"FLOWERSEC_WEAKNET_CLIENT_NAMESPACE="+config.ClientNamespace,
		"FLOWERSEC_WEAKNET_SERVER_NAMESPACE="+config.ServerNamespace,
		"FLOWERSEC_WEAKNET_SERVER_ADDRESS="+config.ServerAddress.Addr().String(),
	)
	if isControllerWeaknetScenario(scenarioName) {
		command.Env = append(command.Env, "FLOWERSEC_WEAKNET_CONTROLLER=1")
	}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("run Flowersec direct weak-network worker: %w: %s", err, output)
	}
	return nil
}

func isControllerWeaknetScenario(name string) bool {
	switch name {
	case "delay-jitter", "periodic-loss", "reorder", "outage-reconnect", "pin-rotation-refresh-backoff-lease":
		return true
	default:
		return false
	}
}

func runDirectWorker(ctx context.Context, kind carrier.Kind, clientNamespace, serverNamespace, serverAddress string, scenario weaknetScenario) (resultErr error) {
	if err := linuxnetlab.RequireCurrentNamespace(clientNamespace); err != nil {
		return err
	}
	if os.Getenv("FLOWERSEC_WEAKNET_CONTROLLER") == "1" {
		return runControllerDirectWorker(ctx, kind, clientNamespace, serverNamespace, serverAddress, os.Getenv("FLOWERSEC_WEAKNET_SCENARIO"))
	}
	var endpoint *transporttest.ProductDirectEndpoint
	if err := linuxnetlab.InNamespace(serverNamespace, func() error {
		var openErr error
		endpoint, openErr = transporttest.OpenProductDirectEndpointAt(ctx, kind, serverAddress)
		return openErr
	}); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, endpoint.Close()) }()
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, pair.Close()) }()
	if err := linuxnetlab.ResetFaultObservation(ctx, clientNamespace, serverNamespace); err != nil {
		return err
	}
	if pair.SpendCount() != 1 {
		return fmt.Errorf("Flowersec weak-network spend count = %d", pair.SpendCount())
	}
	if err := verifyDirectResetAndCancellation(ctx, pair); err != nil {
		return err
	}
	if scenario.expectOutage {
		if err := verifyOutageBehavior(ctx, pair); err != nil {
			return err
		}
	}
	if _, err := transporttest.RunRPC(ctx, pair, 4, 2, 256, 5*time.Second); err != nil {
		return err
	}
	request := bytes.Repeat([]byte{0x5a}, scenario.payloadBytes)
	transferStarted := time.Now()
	if err := pair.RoundTrip(ctx, request, []byte("weaknet-response")); err != nil {
		return err
	}
	if elapsed := time.Since(transferStarted); elapsed < scenario.minimumTransferDuration {
		return fmt.Errorf("Flowersec shaped transfer completed in %s, below %s", elapsed, scenario.minimumTransferDuration)
	}
	if kind == carrier.KindRawQUIC {
		if err := roundTripUnreliable(ctx, pair.Client, pair.Server); err != nil {
			return err
		}
	}
	if scenario.pathMTU > 0 {
		if err := verifyPathMTU(ctx, clientNamespace, serverAddress, scenario.pathMTU, socketScopedPathMTU); err != nil {
			return err
		}
	}
	return nil
}

func runControllerDirectWorker(ctx context.Context, kind carrier.Kind, clientNamespace, serverNamespace, serverAddress, scenarioName string) (resultErr error) {
	if err := linuxnetlab.RequireCurrentNamespace(clientNamespace); err != nil {
		return err
	}
	var endpoint *transporttest.ProductDirectEndpoint
	if err := linuxnetlab.InNamespace(serverNamespace, func() error {
		var openErr error
		endpoint, openErr = transporttest.OpenProductDirectEndpointAt(ctx, kind, serverAddress)
		return openErr
	}); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, endpoint.Close()) }()
	plans := []transporttest.ControllerArtifactPlan{transporttest.ControllerPlanCurrentPin}
	switch scenarioName {
	case "pin-rotation-refresh-backoff-lease":
		plans = []transporttest.ControllerArtifactPlan{transporttest.ControllerPlanUnavailable, transporttest.ControllerPlanStalePin, transporttest.ControllerPlanCurrentPin}
	case "outage-reconnect":
		plans = []transporttest.ControllerArtifactPlan{transporttest.ControllerPlanCurrentPin, transporttest.ControllerPlanCurrentPin}
	}
	source, err := transporttest.NewProductControllerArtifactSource(endpoint, plans)
	if err != nil {
		return err
	}
	controller, err := flowersec.NewConnectionController(source, flowersec.ConnectionControllerOptions{
		Connector: endpoint.ProductControllerConnectorOptions(),
	})
	if err != nil {
		return err
	}
	controller.Start(ctx)
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resultErr = errors.Join(resultErr, controller.Close(closeCtx))
		cancel()
	}()
	if err := waitForControllerState(ctx, controller, flowersec.ConnectionConnected); err != nil {
		return err
	}
	serverIndex := source.AcquisitionCount() - 1
	server, err := source.WaitServer(ctx, serverIndex)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, server.Close()) }()
	client := controller.CurrentSession()
	if client == nil {
		return errors.New("controller connected without a client session")
	}
	if scenarioName == "pin-rotation-refresh-backoff-lease" {
		times := source.AcquisitionTimes()
		if len(times) < 3 || times[1].Sub(times[0]) < 200*time.Millisecond {
			return fmt.Errorf("controller refresh backoff was not observed: %v", times)
		}
		if source.RetireCount(0) != 1 || source.RetireCount(1) != 1 || source.SpendCount(2) != 1 {
			return fmt.Errorf("controller rotation lease finalization = retire(%d,%d) spend(%d)", source.RetireCount(0), source.RetireCount(1), source.SpendCount(2))
		}
	}
	if err := transporttest.NewProductControllerPair(client, server).RoundTrip(ctx, bytes.Repeat([]byte("controller-weaknet"), 1024), []byte("controller-response")); err != nil {
		return err
	}
	if scenarioName == "outage-reconnect" {
		if err := waitForControllerOutageWindow(ctx, 3500*time.Millisecond); err != nil {
			return err
		}
		if err := server.Close(); err != nil {
			return err
		}
		if err := waitForControllerReplacement(ctx, controller, client); err != nil {
			return err
		}
		serverIndex = source.AcquisitionCount() - 1
		server, err = source.WaitServer(ctx, serverIndex)
		if err != nil {
			return err
		}
		if err := transporttest.NewProductControllerPair(controller.CurrentSession(), server).RoundTrip(ctx, []byte("reconnected"), []byte("reconnected-response")); err != nil {
			return err
		}
	}
	return nil
}

func waitForControllerState(ctx context.Context, controller *flowersec.ConnectionController, want flowersec.ConnectionState) error {
	for {
		snapshot := controller.Snapshot()
		if snapshot.State == want {
			return nil
		}
		if snapshot.State == flowersec.ConnectionFailed || snapshot.State == flowersec.ConnectionClosed {
			return fmt.Errorf("controller reached %s while waiting for %s: %v", snapshot.State, want, snapshot.Failure)
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitForControllerReplacement(ctx context.Context, controller *flowersec.ConnectionController, previous flowersec.Session) error {
	for {
		snapshot := controller.Snapshot()
		if snapshot.State == flowersec.ConnectionConnected && snapshot.CurrentSession != nil && snapshot.CurrentSession != previous {
			return nil
		}
		if snapshot.State == flowersec.ConnectionFailed || snapshot.State == flowersec.ConnectionClosed {
			return fmt.Errorf("controller reached %s while waiting for replacement: %v", snapshot.State, snapshot.Failure)
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitForControllerOutageWindow(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func verifyDirectResetAndCancellation(ctx context.Context, pair *transporttest.ProductDirectPair) error {
	stream, err := pair.Client.OpenStream(ctx, "weaknet-reset", flowersec.StreamMetadata{})
	if err != nil {
		return err
	}
	accepted, err := pair.Server.AcceptStream(ctx)
	if err != nil {
		_ = stream.Reset()
		return err
	}
	if err := stream.Reset(); err != nil {
		return err
	}
	if err := observePeerReset(ctx, accepted.Stream); err != nil {
		return err
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pair.Client.AcceptStream(canceled); err == nil {
		return errors.New("Flowersec weak-network canceled accept unexpectedly succeeded")
	}
	if _, err := pair.Client.ProbeLiveness(ctx); err != nil {
		return fmt.Errorf("Flowersec session did not survive stream reset and canceled accept: %w", err)
	}
	return nil
}

type peerResetReader interface {
	Read([]byte) (int, error)
	Close() error
}

func observePeerReset(ctx context.Context, stream peerResetReader) error {
	if stream == nil {
		return errors.New("Flowersec reset peer stream is unavailable")
	}
	readResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, err := stream.Read(buffer)
		readResult <- err
	}()
	select {
	case err := <-readResult:
		if !errors.Is(err, protocolv3.ErrStreamReset) && !errors.Is(err, carrier.ErrStreamReset) {
			return fmt.Errorf("Flowersec peer did not observe stream reset: %w", err)
		}
		return nil
	case <-ctx.Done():
		_ = stream.Close()
		return fmt.Errorf("Flowersec peer reset observation: %w", context.Cause(ctx))
	}
}

func verifyOutageBehavior(ctx context.Context, pair *transporttest.ProductDirectPair) error {
	failedDuringOutage := false
	outageDeadline := time.Now().Add(3500 * time.Millisecond)
	for time.Now().Before(outageDeadline) {
		probeCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		_, probeErr := pair.Client.ProbeLiveness(probeCtx)
		cancel()
		if probeErr != nil {
			failedDuringOutage = true
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !failedDuringOutage {
		return errors.New("Flowersec outage did not interrupt any liveness operation")
	}
	if _, err := pair.Client.ProbeLiveness(ctx); err != nil {
		return fmt.Errorf("Flowersec session did not recover after outage: %w", err)
	}
	return nil
}

func roundTripUnreliable(ctx context.Context, client flowersec.Session, server flowersession.Session) error {
	clientChannel, err := client.UnreliableMessages()
	if err != nil {
		return err
	}
	serverChannel, err := server.UnreliableMessages()
	if err != nil {
		return err
	}
	payload := []byte("kernel-weaknet-datagram")
	if clientChannel.MaxMessageBytes() < len(payload) || serverChannel.MaxMessageBytes() < len(payload) {
		return errors.New("raw QUIC unreliable message limit is too small")
	}
	received := make(chan []byte, 1)
	receiveErr := make(chan error, 1)
	go func() {
		value, receiveError := serverChannel.Receive(ctx)
		if receiveError != nil {
			receiveErr <- receiveError
			return
		}
		received <- value
	}()
	accepted := false
	for attempt := 0; attempt < 8; attempt++ {
		status, sendErr := clientChannel.Send(ctx, payload, flowersec.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)})
		if sendErr != nil {
			return sendErr
		}
		if status == flowersec.UnreliableAccepted {
			accepted = true
		}
		select {
		case value := <-received:
			if !bytes.Equal(value, payload) {
				return errors.New("raw QUIC unreliable payload mismatch")
			}
			if !accepted {
				return errors.New("raw QUIC delivered an unaccepted unreliable message")
			}
			return nil
		case err := <-receiveErr:
			return err
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("raw QUIC unreliable message was not delivered through the fault lab")
}

func runTunnel(ctx context.Context, kind carrier.Kind, config linuxnetlab.Config) error {
	topology := tunnelworkload.TopologyWW
	if kind == carrier.KindRawQUIC {
		topology = tunnelworkload.TopologyQQ
	}
	var endpoint *tunnelworkload.Endpoint
	if err := linuxnetlab.InNamespace(config.ServerNamespace, func() error {
		var openErr error
		endpoint, openErr = tunnelworkload.OpenEndpointAt(ctx, topology, config.ServerAddress.Addr().String())
		return openErr
	}); err != nil {
		return err
	}
	endpoint.SetEndpointDialNamespace(config.ClientNamespace)
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		return errors.Join(err, cleanupTunnelFailure(endpoint.Close))
	}
	if err := verifyTunnelResetCancellationAndDatagram(ctx, pair, kind); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cleanupErr := errors.Join(pair.Close(cleanupCtx), endpoint.Close(cleanupCtx))
		cancel()
		return errors.Join(err, cleanupErr)
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := pair.Close(cleanupCtx); err != nil {
		cleanupCancel()
		return errors.Join(err, cleanupTunnelFailure(endpoint.Close))
	}
	cleanupCancel()
	plan := transporttest.ProfilePlan{
		ID:                     "kernel-weaknet-tunnel-v1",
		Cold:                   transporttest.ColdPlan{Operations: 1, MaxInflight: 1, StartRatePerSecond: 1, OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 15},
		RPC:                    transporttest.RPCPlan{Operations: 2, RequestBytes: 256, ResponseBytes: 256, Workers: 1, OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 10},
		Bulk:                   transporttest.BulkPlan{WarmupBytesPerDirection: 1024, ScoreBytesPerDirection: 64 << 10, PhaseDeadlineSeconds: 10},
		CleanupDeadlineSeconds: 10,
	}
	result, err := tunnelworkload.Run(ctx, endpoint, plan)
	if err != nil {
		return err
	}
	if len(result.Cold) != 1 || len(result.RPC) != 2 || result.Bulk.BytesPerDirection != 64<<10 || result.CleanupDuration <= 0 {
		return errors.New("Flowersec tunnel weak-network workload was incomplete")
	}
	return nil
}

func cleanupTunnelFailure(owners ...func(context.Context) error) error {
	var joined error
	for _, closeOwner := range owners {
		if closeOwner == nil {
			continue
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		joined = errors.Join(joined, closeOwner(cleanupCtx))
		cancel()
	}
	return joined
}

func verifyTunnelResetCancellationAndDatagram(ctx context.Context, pair *tunnelworkload.Pair, kind carrier.Kind) error {
	stream, err := pair.Client.OpenStream(ctx, "weaknet-tunnel-reset", flowersession.Metadata{})
	if err != nil {
		return err
	}
	accepted, err := pair.Server.AcceptStream(ctx)
	if err != nil {
		_ = stream.Reset()
		return err
	}
	if err := stream.Reset(); err != nil {
		return err
	}
	if err := observePeerReset(ctx, accepted.Stream); err != nil {
		return err
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pair.Client.AcceptStream(canceled); err == nil {
		return errors.New("Flowersec tunnel canceled accept unexpectedly succeeded")
	}
	if _, err := pair.Client.ProbeLiveness(ctx); err != nil {
		return fmt.Errorf("Flowersec tunnel did not survive stream reset and cancellation: %w", err)
	}
	if kind != carrier.KindRawQUIC {
		return nil
	}
	clientChannel, err := pair.Client.UnreliableMessages()
	if err != nil {
		return err
	}
	serverChannel, err := pair.Server.UnreliableMessages()
	if err != nil {
		return err
	}
	payload := []byte("kernel-tunnel-weaknet-datagram")
	received := make(chan []byte, 1)
	receiveErr := make(chan error, 1)
	go func() {
		value, receiveError := serverChannel.Receive(ctx)
		if receiveError != nil {
			receiveErr <- receiveError
			return
		}
		received <- value
	}()
	acceptedSend := false
	for attempt := 0; attempt < 8; attempt++ {
		status, sendErr := clientChannel.Send(ctx, payload, flowersession.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)})
		if sendErr != nil {
			return sendErr
		}
		acceptedSend = accumulateUnreliableAcceptance(acceptedSend, status == flowersession.UnreliableAccepted)
		select {
		case value := <-received:
			if !acceptedSend || !bytes.Equal(value, payload) {
				return errors.New("raw QUIC tunnel unreliable message mismatch")
			}
			return nil
		case err := <-receiveErr:
			return err
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("raw QUIC tunnel unreliable message was not delivered through the fault lab")
}

func accumulateUnreliableAcceptance(previous, current bool) bool { return previous || current }

func validateObservation(scenario string, observation linuxnetlab.KernelFaultObservation) error {
	if observation.Client.Packets == 0 || observation.Server.Packets == 0 || observation.Client.DelayPackets == 0 || observation.Server.DelayPackets == 0 {
		return errors.New("Flowersec workload did not traverse both kernel fault directions")
	}
	switch scenario {
	case "periodic-loss":
		if observation.Client.PeriodicLossPackets+observation.Server.PeriodicLossPackets == 0 {
			return errors.New("periodic loss was not observed")
		}
	case "burst-loss":
		if observation.Client.BurstLossPackets+observation.Server.BurstLossPackets == 0 {
			return errors.New("burst loss was not observed")
		}
	case "outage", "outage-reconnect":
		if observation.Client.OutageDropPackets+observation.Server.OutageDropPackets == 0 {
			return errors.New("outage drops were not observed")
		}
	case "representative":
		if observation.Client.PeriodicLossPackets+observation.Server.PeriodicLossPackets == 0 {
			return errors.New("representative tunnel periodic loss was not observed")
		}
	case "delay-jitter", "pin-rotation-refresh-backoff-lease":
		if observation.Client.JitterPackets+observation.Server.JitterPackets == 0 {
			return errors.New("jitter was not observed")
		}
	case "reorder":
		if observation.Client.ReorderPackets+observation.Server.ReorderPackets == 0 {
			return errors.New("reordering was not observed")
		}
	case "mtu-large-payload":
		if observation.Client.Bytes+observation.Server.Bytes < 2<<20 {
			return errors.New("MTU workload did not carry the large Flowersec payload")
		}
	case "reorder-duplicate":
		if observation.Client.ReorderPackets+observation.Server.ReorderPackets == 0 || observation.Client.DuplicatePackets+observation.Server.DuplicatePackets == 0 {
			return errors.New("reorder and duplicate were not both observed")
		}
	case "rate-5mbps", "rate-1mbps":
		if observation.ClientQdisc.Overlimits+observation.ServerQdisc.Overlimits == 0 {
			return errors.New("kernel rate shaping was not observed")
		}
	}
	return nil
}
