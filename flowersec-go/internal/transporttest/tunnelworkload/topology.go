// Package tunnelworkload runs original current Flowersec tunnel workloads.
package tunnelworkload

import (
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
)

var errEndpointClosed = errors.New("original tunnel workload endpoint closed")

// Topology identifies the endpoint-side client/server tunnel carrier pair.
type Topology string

const (
	TopologyWW Topology = "WW"
	TopologyQQ Topology = "QQ"
	TopologyWQ Topology = "WQ"
	TopologyQW Topology = "QW"
)

// Topologies returns the frozen tunnel matrix in report order.
func Topologies() []Topology {
	return []Topology{TopologyWW, TopologyQQ, TopologyWQ, TopologyQW}
}

// Carriers returns the client-role and server-role physical carriers.
func (topology Topology) Carriers() (carrier.Kind, carrier.Kind, error) {
	switch topology {
	case TopologyWW:
		return carrier.KindWebSocket, carrier.KindWebSocket, nil
	case TopologyQQ:
		return carrier.KindRawQUIC, carrier.KindRawQUIC, nil
	case TopologyWQ:
		return carrier.KindWebSocket, carrier.KindRawQUIC, nil
	case TopologyQW:
		return carrier.KindRawQUIC, carrier.KindWebSocket, nil
	default:
		return "", "", errors.New("tunnel topology is outside the frozen WW/QQ/WQ/QW matrix")
	}
}
