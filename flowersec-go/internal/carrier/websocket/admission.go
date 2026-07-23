package websocket

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	gorillaws "github.com/gorilla/websocket"
)

var ErrInvalidAdmissionMessage = errors.New("invalid WebSocket admission message")

// CommitAdmission sends one complete FSB2 binary message and requires one
// complete FSA2 binary response before the connection can switch to Yamux.
func CommitAdmission(ctx context.Context, conn *gorillaws.Conn, rawFSB2 []byte, reasons artifactv2.ReasonRegistry) (response artifactv2.AdmissionResponse, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if conn == nil {
		return response, net.ErrClosed
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = conn.Close()
		}
	}()
	cancellation := newAdmissionCancellation(ctx, func() { _ = conn.Close() })
	defer func() {
		if cancelErr := cancellation.stopAndWait(); cancelErr != nil {
			err = cancelErr
			succeeded = false
		}
	}()
	if err := validateTLS13(conn); err != nil {
		return response, err
	}
	kind, err := pathKindForSubprotocol(conn.Subprotocol())
	if err != nil {
		return response, err
	}
	decoded, err := artifactv2.ParseRequest(rawFSB2)
	if err != nil {
		return response, invalidAdmissionMessage(err)
	}
	if decoded.Request.PathKind != kind {
		return response, invalidAdmissionMessage(fmt.Errorf("FSB2 path %q does not match subprotocol %q", decoded.Request.PathKind, conn.Subprotocol()))
	}

	if err := ctx.Err(); err != nil {
		return response, err
	}
	if err := conn.WriteMessage(gorillaws.BinaryMessage, rawFSB2); err != nil {
		return response, preferAdmissionContextError(ctx, err)
	}
	conn.SetReadLimit(artifactv2.FSA2HeaderSize + artifactv2.MaxAdmissionReasonBytes)
	messageType, rawFSA2, err := conn.ReadMessage()
	if err != nil {
		return response, preferAdmissionContextError(ctx, err)
	}
	if messageType != gorillaws.BinaryMessage {
		return response, invalidAdmissionMessage(ErrNonBinaryMessage)
	}
	response, err = artifactv2.ParseResponse(rawFSA2, reasons)
	if err != nil {
		return response, invalidAdmissionMessage(err)
	}
	if err := ctx.Err(); err != nil {
		return response, err
	}
	if response.Status != artifactv2.AdmissionSuccess {
		return response, &admissionv2.ResponseError{Status: response.Status, Reason: response.Reason}
	}
	succeeded = true
	return response, nil
}

// ServeAdmission consumes exactly one bounded FSB2 binary message and emits
// exactly one bounded FSA2 binary response. The authorizer is never called for
// invalid framing or a path that does not match the negotiated subprotocol.
func ServeAdmission(ctx context.Context, conn *gorillaws.Conn, reasons artifactv2.ReasonRegistry, authorize admissionv2.Authorize) (decoded *artifactv2.DecodedRequest, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if conn == nil {
		return nil, net.ErrClosed
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = conn.Close()
		}
	}()
	cancellation := newAdmissionCancellation(ctx, func() { _ = conn.Close() })
	defer func() {
		if cancelErr := cancellation.stopAndWait(); cancelErr != nil {
			err = cancelErr
			succeeded = false
		}
	}()
	if authorize == nil {
		return nil, admissionv2.ErrInvalidAuthorizer
	}
	if err := validateTLS13(conn); err != nil {
		return nil, err
	}
	kind, err := pathKindForSubprotocol(conn.Subprotocol())
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn.SetReadLimit(artifactv2.FSB2HeaderSize + artifactv2.MaxCanonicalFSB2Payload)
	messageType, rawFSB2, err := conn.ReadMessage()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, invalidAdmissionMessage(err)
	}
	if messageType != gorillaws.BinaryMessage {
		return nil, invalidAdmissionMessage(ErrNonBinaryMessage)
	}
	decoded, err = artifactv2.ParseRequest(rawFSB2)
	if err != nil {
		return nil, invalidAdmissionMessage(err)
	}
	if decoded.Request.PathKind != kind {
		return nil, invalidAdmissionMessage(fmt.Errorf("FSB2 path %q does not match subprotocol %q", decoded.Request.PathKind, conn.Subprotocol()))
	}
	response, err := authorize(ctx, decoded)
	if err != nil {
		return nil, err
	}
	rawFSA2, err := artifactv2.MarshalResponse(response, reasons)
	if err != nil {
		return nil, err
	}
	if err := conn.WriteMessage(gorillaws.BinaryMessage, rawFSA2); err != nil {
		return nil, preferAdmissionContextError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if response.Status != artifactv2.AdmissionSuccess {
		return decoded, &admissionv2.ResponseError{Status: response.Status, Reason: response.Reason}
	}
	succeeded = true
	return decoded, nil
}

func pathKindForSubprotocol(subprotocol string) (artifactv2.PathKind, error) {
	switch subprotocol {
	case SubprotocolDirect:
		return artifactv2.PathDirect, nil
	case SubprotocolTunnel:
		return artifactv2.PathTunnel, nil
	default:
		return "", ErrInvalidSubprotocol
	}
}

type admissionCancellation struct {
	ctx  context.Context
	stop func() bool
	done chan struct{}
}

func newAdmissionCancellation(ctx context.Context, closeConnection func()) *admissionCancellation {
	done := make(chan struct{})
	guard := &admissionCancellation{ctx: ctx, done: done}
	guard.stop = context.AfterFunc(ctx, func() {
		defer close(done)
		closeConnection()
	})
	return guard
}

func (guard *admissionCancellation) stopAndWait() error {
	if guard.stop() {
		return nil
	}
	<-guard.done
	return guard.ctx.Err()
}

func preferAdmissionContextError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}

func invalidAdmissionMessage(cause error) error {
	return fmt.Errorf("%w: %w", ErrInvalidAdmissionMessage, cause)
}
