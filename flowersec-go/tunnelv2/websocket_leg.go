package tunnelv2

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v2/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/carrier/websocket"
	gorillaws "github.com/gorilla/websocket"
)

// WebSocketPendingLeg adapts a deferred server-side tunnel WebSocket to the
// carrier-neutral pairing coordinator.
type WebSocketPendingLeg struct {
	server *carrierws.DeferredTunnelServer
}

// NewWebSocketPendingLeg validates TLS/subprotocol and starts the single
// WebSocket reader pump before FSB2 is received.
func NewWebSocketPendingLeg(conn *gorillaws.Conn, resources carrierws.ResourcePolicy, liveness carrierws.LivenessPolicy) (*WebSocketPendingLeg, error) {
	server, err := carrierws.NewDeferredTunnelServer(conn, resources, liveness)
	if err != nil {
		return nil, err
	}
	return &WebSocketPendingLeg{server: server}, nil
}

func (leg *WebSocketPendingLeg) CarrierKind() carrier.Kind { return carrier.KindWebSocket }

func (leg *WebSocketPendingLeg) ReceiveAdmission(ctx context.Context) (*artifactv2.DecodedRequest, error) {
	return leg.server.ReceiveAdmission(ctx)
}

func (leg *WebSocketPendingLeg) SendAdmission(ctx context.Context, response artifactv2.AdmissionResponse, reasons artifactv2.ReasonRegistry) error {
	return leg.server.SendAdmission(ctx, response, reasons)
}

func (leg *WebSocketPendingLeg) Activate(ctx context.Context) (carrier.Session, error) {
	return leg.server.Activate(ctx)
}

func (leg *WebSocketPendingLeg) CloseWithError(ctx context.Context, applicationError carrier.ApplicationError) error {
	return leg.server.CloseWithErrorContext(ctx, applicationError)
}

func (leg *WebSocketPendingLeg) RejectWaitingStreams(ctx context.Context) error {
	return leg.server.WaitWhilePending(ctx)
}

var _ PendingLeg = (*WebSocketPendingLeg)(nil)
var _ WaitingStreamRejector = (*WebSocketPendingLeg)(nil)
