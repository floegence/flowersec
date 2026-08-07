package performance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest/tunnelworkload"
)

const browserWorkerArg = "--browser-capacity-worker"

type browserWorkerRequest struct {
	Mode            string                     `json:"mode"`
	Topology        string                     `json:"topology"`
	ClientNamespace string                     `json:"client_namespace"`
	ServerNamespace string                     `json:"server_namespace"`
	ServerAddress   string                     `json:"server_address"`
	SourceRoot      string                     `json:"source_root"`
	Capacity        *browserCapacityWorkerPlan `json:"capacity"`
}

func runBrowserWorker(ctx context.Context, input io.Reader, output io.Writer) error {
	var request browserWorkerRequest
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("browser capacity worker request is invalid")
	}
	if request.Mode != "capacity" || request.Capacity == nil {
		return errors.New("browser worker only supports explicit capacity runs")
	}
	return runBrowserCapacityWorker(ctx, request, output)
}

func browserCapacityTopology(definition capacityCaseDefinition) string {
	if definition.BrowserDirect {
		return string(browserDirectWebTransportTopology)
	}
	return string(definition.BrowserTopology)
}

func capacityContractForDefinition(definition capacityCaseDefinition) capacityContract {
	if definition.Kind == capacityBrowserStream {
		contract := productionBrowserStreamCapacityContract()
		if definition.BrowserTopology == tunnelworkload.BrowserTunnelWTWSS {
			contract.YamuxMaxFrameBytes = 256 * 1024
			contract.YamuxMaxStreamReceiveBytes = 256 * 1024
			contract.YamuxMaxSessionReceiveBytes = 130 * 256 * 1024
		}
		if definition.BrowserTopology == tunnelworkload.BrowserTunnelWTWSS || definition.BrowserTopology == tunnelworkload.BrowserTunnelWTQUIC {
			contract.TunnelCopyBufferBytes = 4 * 1024
		}
		return contract
	}
	if definition.Kind == capacityBrowserTunnel {
		return productionBrowserCapacityContract()
	}
	return productionCapacityContract()
}

func capacityCaseTimeout(definition capacityCaseDefinition) time.Duration {
	return capacityContractForDefinition(definition).Watchdog + 30*time.Second
}
