package tunnelv3

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v5/internal/carrier/websocketv3"
	gorillaws "github.com/gorilla/websocket"
)

var ErrInvalidWebSocketLeg = errors.New("invalid Flowersec v3 WebSocket tunnel leg")

// WebSocketPendingLeg adapts a pre-Yamux server-side tunnel WebSocket to the
// carrier-neutral pairing coordinator.
type WebSocketPendingLeg struct {
	server *carrierws.PendingServer
}

// NewWebSocketPendingLeg validates TLS/subprotocol and starts the single
// WebSocket reader pump before FSB3 is received.
func NewWebSocketPendingLeg(conn *gorillaws.Conn, resources carrierws.ResourcePolicy) (*WebSocketPendingLeg, error) {
	server, err := carrierws.NewPendingServer(
		conn,
		resources,
		artifactv3.FSB3HeaderSize+artifactv3.MaxCanonicalFSB3Payload,
	)
	if err != nil {
		return nil, err
	}
	return &WebSocketPendingLeg{server: server}, nil
}

func (leg *WebSocketPendingLeg) CarrierKind() carrier.Kind { return carrier.KindWebSocket }

func (leg *WebSocketPendingLeg) ReceiveAdmission(ctx context.Context) (*artifactv3.DecodedRequest, error) {
	raw, err := leg.server.ReceiveInitialMessage(ctx)
	if err != nil {
		return nil, err
	}
	decoded, err := artifactv3.ParseRequest(raw)
	if err != nil {
		_ = leg.server.CloseWithErrorContext(ctx, carrier.ApplicationError{Code: 6, Reason: "invalid admission"})
		return nil, err
	}
	if decoded.Request.PathKind != artifactv3.PathTunnel {
		_ = leg.server.CloseWithErrorContext(ctx, carrier.ApplicationError{Code: 6, Reason: "invalid admission"})
		return nil, ErrInvalidWebSocketLeg
	}
	return decoded, nil
}

func (leg *WebSocketPendingLeg) SendAdmission(ctx context.Context, response artifactv3.AdmissionResponse, reasons artifactv3.ReasonRegistry) error {
	raw, err := artifactv3.MarshalResponse(response, reasons)
	if err != nil {
		return err
	}
	return leg.server.SendInitialResponse(ctx, raw, response.Status == artifactv3.AdmissionSuccess)
}

func (leg *WebSocketPendingLeg) Activate(ctx context.Context, role uint8) (carrier.Session, error) {
	if role != 1 && role != 2 {
		return nil, ErrInvalidWebSocketLeg
	}
	yamuxRole := carrierws.ServerRole
	if role == 2 {
		yamuxRole = carrierws.ClientRole
	}
	return leg.server.Activate(ctx, yamuxRole)
}

func (leg *WebSocketPendingLeg) CloseWithError(ctx context.Context, applicationError carrier.ApplicationError) error {
	return leg.server.CloseWithErrorContext(ctx, applicationError)
}

func (leg *WebSocketPendingLeg) RejectWaitingStreams(ctx context.Context) error {
	return leg.server.WaitWhilePending(ctx)
}

var _ PendingLeg = (*WebSocketPendingLeg)(nil)
var _ WaitingStreamRejector = (*WebSocketPendingLeg)(nil)
