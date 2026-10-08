package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	defaultOrigin = "https://client.example"
	echoRPC       = uint32(7001)
	notifyRPC     = uint32(7002)
	completeRPC   = uint32(7003)
	datagramRPC   = uint32(7005)
	echoKind      = "parity.echo"
	resetKind     = "parity.reset"
	peerTimeout   = 30 * time.Second
)

type executionLedger struct {
	mu    sync.Mutex
	cases []string
	seen  map[string]struct{}
}

func newExecutionLedger() *executionLedger { return &executionLedger{seen: make(map[string]struct{})} }
func (l *executionLedger) record(ids ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, id := range ids {
		if _, ok := l.seen[id]; !ok {
			l.seen[id] = struct{}{}
			l.cases = append(l.cases, id)
		}
	}
}
func (l *executionLedger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.cases...)
}

type peerArguments struct {
	Role              string
	Carrier           string
	Carriers          [2]string
	EndpointListeners [2]bool
	DeploymentPath    string
	Directory         string
	SDKExample        bool
}

func validCarrier(carrier string) bool {
	return carrier == "raw-quic" || carrier == "websocket" || carrier == "webtransport"
}
func parsePeerArguments(arguments []string) (peerArguments, error) {
	var result peerArguments
	if len(arguments) < 3 || len(arguments)%2 != 1 {
		return result, errors.New("usage: server-parity-peer ROLE --carrier CARRIER [--workload sdk-example] [--server-carrier CARRIER] [--client-listener endpoint|relay] [--server-listener endpoint|relay]")
	}
	result.Role = arguments[0]
	result.Carrier = arguments[2]
	if arguments[1] != "--carrier" || !validCarrier(result.Carrier) {
		return result, errors.New("an explicit native carrier is required")
	}
	switch result.Role {
	case "server", "client", "relay", "live-authority", "live-installation", "pool-installation", "tunnel-endpoint-a", "tunnel-endpoint-b":
	default:
		return result, errors.New("unknown server parity peer role")
	}
	result.Carriers = [2]string{result.Carrier, result.Carrier}
	result.EndpointListeners = [2]bool{false, true}
	seen := map[string]bool{}
	for index := 3; index < len(arguments); index += 2 {
		name, value := arguments[index], arguments[index+1]
		if seen[name] {
			return result, errors.New("current peer options must occur once")
		}
		seen[name] = true
		if name == "--workload" {
			if result.Role != "server" || result.Carrier != "websocket" || value != "sdk-example" {
				return result, errors.New("the SDK example workload requires the direct WebSocket server")
			}
			result.SDKExample = true
			continue
		}
		if name == "--wire-revision" {
			if value != "4" {
				return result, errors.New("current peer requires wire revision 4")
			}
			continue
		}
		if name == "--directory" {
			if result.Role != "live-installation" && result.Role != "pool-installation" || value == "" || len(value) > 4096 {
				return result, errors.New("original live fixture requires its absolute empty installation directory")
			}
			result.Directory = value
			continue
		}
		if name == "--deployment" {
			if result.Role != "relay" && result.Role != "live-authority" && result.Role != "tunnel-endpoint-b" || value == "" || len(value) > 4096 {
				return result, errors.New("independent deployment belongs to relay, original authority or registered B")
			}
			result.DeploymentPath = value
			continue
		}
		if result.Role != "relay" && result.Role != "live-authority" && result.Role != "live-installation" && result.Role != "pool-installation" {
			return result, errors.New("only relay, original authority and live installation accept a physical topology policy")
		}
		switch name {
		case "--server-carrier":
			if !validCarrier(value) {
				return result, errors.New("unknown server native carrier")
			}
			result.Carriers[1] = value
		case "--client-listener", "--server-listener":
			if value != "endpoint" && value != "relay" {
				return result, errors.New("physical listener must be endpoint or relay")
			}
			side := 0
			if name == "--server-listener" {
				side = 1
			}
			result.EndpointListeners[side] = value == "endpoint"
		default:
			return result, errors.New("unknown current peer topology argument")
		}
	}
	return result, nil
}
func parseArguments(arguments []string) (string, string, error) {
	value, err := parsePeerArguments(arguments)
	return value.Role, value.Carrier, err
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if os.Getenv("FLOWERSEC_PARITY_TEST_ONLY") != "1" {
		return errors.New("server parity peer is test-only")
	}
	arguments, err := parsePeerArguments(os.Args[1:])
	if err != nil {
		return err
	}
	timeout := peerTimeout
	if arguments.Role == "live-installation" || arguments.Role == "pool-installation" {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	switch arguments.Role {
	case "server":
		return runCurrentDirectServer(ctx, arguments.Carrier, arguments.SDKExample)
	case "client":
		return runCurrentDirectClient(ctx, arguments.Carrier)
	case "live-installation":
		return runCurrentLiveInstallation(ctx, arguments.Directory, arguments.Carriers, arguments.EndpointListeners)
	case "pool-installation":
		return runCurrentPoolInstallation(ctx, arguments.Directory, arguments.Carriers, arguments.EndpointListeners)
	case "live-authority":
		return runCurrentLiveAuthority(ctx, arguments.Carriers, arguments.EndpointListeners, arguments.DeploymentPath)
	case "relay":
		return runCurrentTunnelRelay(ctx, arguments.Carriers, arguments.EndpointListeners, arguments.DeploymentPath)
	case "tunnel-endpoint-a":
		return runCurrentTunnelEndpointA(ctx, arguments.Carrier)
	case "tunnel-endpoint-b":
		return runCurrentTunnelEndpointB(ctx, arguments.Carrier, arguments.DeploymentPath)
	}
	return errors.New("unknown server parity peer role")
}
func parityOrigin() string {
	if value := os.Getenv("FLOWERSEC_PARITY_ORIGIN"); value != "" {
		return value
	}
	return defaultOrigin
}
func waitSignal(ctx context.Context, signal <-chan struct{}, name string) error {
	select {
	case <-signal:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s: %w", name, ctx.Err())
	}
}
func writeJSON(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }
