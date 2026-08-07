package tunnelv2

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	gorillaws "github.com/gorilla/websocket"
)

var ErrInvalidWebSocketLeg = errors.New("invalid Flowersec v2 WebSocket tunnel leg")

// WebSocketPendingLeg adapts a pre-Yamux server-side tunnel WebSocket to the
// carrier-neutral pairing coordinator.
type WebSocketPendingLeg struct {
	server *carrierws.PendingServer
}

// NewWebSocketPendingLeg validates TLS/subprotocol and starts the single
// WebSocket reader pump before FSB2 is received.
func NewWebSocketPendingLeg(conn *gorillaws.Conn, resources carrierws.ResourcePolicy) (*WebSocketPendingLeg, error) {
	server, err := carrierws.NewPendingServer(
		conn,
		resources,
		artifactv2.FSB2HeaderSize+artifactv2.MaxCanonicalFSB2Payload,
	)
	if err != nil {
		return nil, err
	}
	return &WebSocketPendingLeg{server: server}, nil
}

func (leg *WebSocketPendingLeg) CarrierKind() carrier.Kind { return carrier.KindWebSocket }

func (leg *WebSocketPendingLeg) ReceiveAdmission(ctx context.Context) (*artifactv2.DecodedRequest, error) {
	raw, err := leg.server.ReceiveInitialMessage(ctx)
	if err != nil {
		return nil, err
	}
	decoded, err := artifactv2.ParseRequest(raw)
	if err != nil {
		_ = leg.server.CloseWithErrorContext(ctx, carrier.ApplicationError{Code: 6, Reason: "invalid admission"})
		return nil, err
	}
	if decoded.Request.PathKind != artifactv2.PathTunnel {
		_ = leg.server.CloseWithErrorContext(ctx, carrier.ApplicationError{Code: 6, Reason: "invalid admission"})
		return nil, ErrInvalidWebSocketLeg
	}
	return decoded, nil
}

func (leg *WebSocketPendingLeg) SendAdmission(ctx context.Context, response artifactv2.AdmissionResponse, reasons artifactv2.ReasonRegistry) error {
	raw, err := artifactv2.MarshalResponse(response, reasons)
	if err != nil {
		return err
	}
	return leg.server.SendInitialResponse(ctx, raw, response.Status == artifactv2.AdmissionSuccess)
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
