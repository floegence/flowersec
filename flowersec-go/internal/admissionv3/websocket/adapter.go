// Package websocket adapts the message-oriented WebSocket ready boundary to
// the transport-neutral Flowersec admission codec.
package websocket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
	carrierws "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/websocketv3"
	gorillaws "github.com/gorilla/websocket"
)

var ErrInvalidAdmissionMessage = errors.New("invalid WebSocket admission message")

type clientExchange struct {
	conn *gorillaws.Conn
}

// NewClientExchange binds the admission protocol to one ready WebSocket.
func NewClientExchange(conn *gorillaws.Conn) admissionv3.ClientExchange {
	return &clientExchange{conn: conn}
}

func (exchange *clientExchange) Commit(ctx context.Context, rawFSB3 []byte) error {
	if exchange == nil {
		return net.ErrClosed
	}
	_, err := CommitClient(ctx, exchange.conn, rawFSB3)
	return err
}

// CommitClient performs the client admission exchange without making server
// rejection reason registries part of runtime composition.
func CommitClient(ctx context.Context, conn *gorillaws.Conn, rawFSB3 []byte) (response artifactv3.AdmissionResponse, err error) {
	return commit(ctx, conn, rawFSB3, artifactv3.ParseClientResponse)
}

// Commit sends one complete FSB3 binary message and requires one
// complete FSA3 binary response before the connection can switch to Yamux.
func Commit(ctx context.Context, conn *gorillaws.Conn, rawFSB3 []byte, reasons artifactv3.ReasonRegistry) (response artifactv3.AdmissionResponse, err error) {
	return commit(ctx, conn, rawFSB3, func(raw []byte) (artifactv3.AdmissionResponse, error) {
		return artifactv3.ParseResponse(raw, reasons)
	})
}

func commit(ctx context.Context, conn *gorillaws.Conn, rawFSB3 []byte, parseResponse func([]byte) (artifactv3.AdmissionResponse, error)) (response artifactv3.AdmissionResponse, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if conn == nil {
		return response, net.ErrClosed
	}
	closeConnection := closeOnce(func() error { return conn.Close() })
	succeeded := false
	defer func() {
		if !succeeded {
			closeConnection()
		}
	}()
	cancellation := newAdmissionCancellation(ctx, closeConnection)
	defer func() {
		if cancelErr := cancellation.stopAndWait(); cancelErr != nil {
			err = cancelErr
			succeeded = false
		}
	}()
	if err := carrierws.ValidateReady(conn, conn.Subprotocol()); err != nil {
		return response, err
	}
	kind, err := pathKindForSubprotocol(conn.Subprotocol())
	if err != nil {
		return response, err
	}
	decoded, err := artifactv3.ParseRequest(rawFSB3)
	if err != nil {
		return response, invalidAdmissionMessage(err)
	}
	if decoded.Request.PathKind != kind {
		return response, invalidAdmissionMessage(fmt.Errorf("FSB3 path %q does not match subprotocol %q", decoded.Request.PathKind, conn.Subprotocol()))
	}

	if err := ctx.Err(); err != nil {
		return response, err
	}
	if err := conn.WriteMessage(gorillaws.BinaryMessage, rawFSB3); err != nil {
		return response, preferAdmissionContextError(ctx, err)
	}
	conn.SetReadLimit(artifactv3.FSA3HeaderSize + artifactv3.MaxAdmissionReasonBytes)
	messageType, rawFSA3, err := conn.ReadMessage()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return response, ctxErr
		}
		return response, invalidAdmissionMessage(err)
	}
	if messageType != gorillaws.BinaryMessage {
		return response, invalidAdmissionMessage(carrierws.ErrNonBinaryMessage)
	}
	response, err = parseResponse(rawFSA3)
	if err != nil {
		return response, invalidAdmissionMessage(err)
	}
	if err := ctx.Err(); err != nil {
		return response, err
	}
	if response.Status != artifactv3.AdmissionSuccess {
		return response, &admissionv3.ResponseError{Status: response.Status, Reason: response.Reason}
	}
	succeeded = true
	return response, nil
}

// Serve consumes exactly one bounded FSB3 binary message and emits
// exactly one bounded FSA3 binary response. The authorizer is never called for
// invalid framing or a path that does not match the negotiated subprotocol.
func Serve(ctx context.Context, conn *gorillaws.Conn, reasons artifactv3.ReasonRegistry, authorize admissionv3.Authorize) (decoded *artifactv3.DecodedRequest, err error) {
	return serve(ctx, conn, reasons, authorize, carrierws.ValidateReady)
}

// ServePrivateLoopback runs the unchanged FSB3/FSA3 admission exchange for
// the isolated private-loopback direct profile. Ordinary admission remains
// TLS-only through Serve.
func ServePrivateLoopback(ctx context.Context, conn *gorillaws.Conn, reasons artifactv3.ReasonRegistry, authorize admissionv3.Authorize) (decoded *artifactv3.DecodedRequest, err error) {
	return serve(ctx, conn, reasons, authorize, carrierws.ValidatePrivateLoopbackReady)
}

func serve(
	ctx context.Context,
	conn *gorillaws.Conn,
	reasons artifactv3.ReasonRegistry,
	authorize admissionv3.Authorize,
	validate func(*gorillaws.Conn, string) error,
) (decoded *artifactv3.DecodedRequest, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if conn == nil {
		return nil, net.ErrClosed
	}
	closeConnection := closeOnce(func() error { return conn.Close() })
	succeeded := false
	defer func() {
		if !succeeded {
			closeConnection()
		}
	}()
	cancellation := newAdmissionCancellation(ctx, closeConnection)
	defer func() {
		if cancelErr := cancellation.stopAndWait(); cancelErr != nil {
			err = cancelErr
			succeeded = false
		}
	}()
	if authorize == nil {
		return nil, admissionv3.ErrInvalidAuthorizer
	}
	if validate == nil {
		return nil, carrierws.ErrInvalidSubprotocol
	}
	if err := validate(conn, conn.Subprotocol()); err != nil {
		return nil, err
	}
	kind, err := pathKindForSubprotocol(conn.Subprotocol())
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn.SetReadLimit(artifactv3.FSB3HeaderSize + artifactv3.MaxCanonicalFSB3Payload)
	messageType, rawFSB3, err := conn.ReadMessage()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, invalidAdmissionMessage(err)
	}
	if messageType != gorillaws.BinaryMessage {
		return nil, invalidAdmissionMessage(carrierws.ErrNonBinaryMessage)
	}
	decoded, err = artifactv3.ParseRequest(rawFSB3)
	if err != nil {
		return nil, invalidAdmissionMessage(err)
	}
	if decoded.Request.PathKind != kind {
		return nil, invalidAdmissionMessage(fmt.Errorf("FSB3 path %q does not match subprotocol %q", decoded.Request.PathKind, conn.Subprotocol()))
	}
	response, err := authorize(ctx, decoded)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rawFSA3, err := artifactv3.MarshalResponse(response, reasons)
	if err != nil {
		return nil, err
	}
	if err := conn.WriteMessage(gorillaws.BinaryMessage, rawFSA3); err != nil {
		return nil, preferAdmissionContextError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if response.Status != artifactv3.AdmissionSuccess {
		return decoded, &admissionv3.ResponseError{Status: response.Status, Reason: response.Reason}
	}
	succeeded = true
	return decoded, nil
}

func pathKindForSubprotocol(subprotocol string) (artifactv3.PathKind, error) {
	switch subprotocol {
	case carrierws.SubprotocolDirect:
		return artifactv3.PathDirect, nil
	case carrierws.SubprotocolTunnel:
		return artifactv3.PathTunnel, nil
	default:
		return "", carrierws.ErrInvalidSubprotocol
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

func closeOnce(closeConnection func() error) func() {
	var once sync.Once
	return func() {
		once.Do(func() { _ = closeConnection() })
	}
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
