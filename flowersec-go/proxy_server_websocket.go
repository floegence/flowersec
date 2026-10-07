package flowersec

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

func (server *ProxyServer) serveWebSocketStream(ctx context.Context, stream proxyStream) error {
	if stream == nil {
		server.report(ErrInvalidProxyServer)
		return ErrInvalidProxyServer
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resetStream := sync.OnceFunc(func() { _ = stream.Reset() })
	ownerStopped := make(chan struct{})
	stopOwner := context.AfterFunc(ctx, func() {
		defer close(ownerStopped)
		resetStream()
	})
	defer func() {
		if !stopOwner() {
			<-ownerStopped
		}
	}()
	// Intake belongs to the same bounded handshake as the upstream dial. Close
	// must also interrupt a peer that has not sent its metadata prefix yet.
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, server.config.defaultTimeout)
	defer cancelHandshake()
	intakeStopped := make(chan struct{})
	stopIntake := context.AfterFunc(handshakeCtx, func() {
		defer close(intakeStopped)
		resetStream()
	})
	joinIntake := sync.OnceFunc(func() {
		if !stopIntake() {
			<-intakeStopped
		}
	})
	defer joinIntake()
	open := proxyWebSocketOpen{}
	if err := readProxyMetadata(stream, server.config.maxMetadata, &open); err != nil {
		server.writeWebSocketError(stream, "unknown", "invalid_ws_open_meta")
		server.report(err)
		return nil
	}
	open.ConnID = strings.TrimSpace(open.ConnID)
	path, err := parseProxyPath(open.Path)
	if open.Version != proxyWireVersion || open.ConnID == "" || err != nil {
		server.writeWebSocketError(stream, open.ConnID, "invalid_ws_open_meta")
		server.report(ErrInvalidProxyServer)
		return nil
	}
	target := *server.config.upstream
	if target.Scheme == "http" {
		target.Scheme = "ws"
	} else {
		target.Scheme = "wss"
	}
	target.Path, target.RawPath, target.RawQuery, target.Fragment = path.Path, path.RawPath, path.RawQuery, ""
	target.ForceQuery = path.ForceQuery
	headers, err := proxyWebSocketHeaders(open.Headers, server.config)
	if err != nil {
		server.writeWebSocketError(stream, open.ConnID, "invalid_ws_open_meta")
		return err
	}
	headers.Set("Origin", server.config.upstreamOrigin)
	credentials, err := server.captureCredentials(ctx, stream, &target, open.CredentialContext, open.Credentials, open.RequestOrigin, open.Headers, headers)
	if err != nil {
		server.writeWebSocketError(stream, open.ConnID, "credential_scope_unavailable")
		return err
	}
	defer credentials.finish()
	dialCtx, cancelDial := context.WithCancel(handshakeCtx)
	dialStopped := make(chan struct{})
	var stopDial func() bool
	if credentials != nil {
		stopDial = context.AfterFunc(credentials.ctx, func() { defer close(dialStopped); cancelDial() })
	}
	defer func() {
		cancelDial()
		if stopDial != nil && !stopDial() {
			<-dialStopped
		}
	}()
	if err = credentials.check(); err != nil {
		return err
	}
	// A fresh dialer belongs to this original handshake. It never shares a
	// cookie-bearing connection or late dial completion with another owner.
	dialer := *server.wsDialer
	connection, response, err := dialer.DialContext(dialCtx, target.String(), headers)
	if response != nil && credentials != nil {
		if updateErr := credentials.update(&target, response.Header); updateErr != nil {
			if connection != nil {
				_ = connection.Close()
			}
			server.writeWebSocketError(stream, open.ConnID, "credential_update_failed")
			return updateErr
		}
	}

	if err != nil {
		code := "upstream_ws_dial_failed"
		if response != nil {
			code = "upstream_ws_rejected"
		}
		if errors.Is(err, context.DeadlineExceeded) {
			code = "timeout"
		}
		if errors.Is(err, context.Canceled) {
			code = "canceled"
		}
		server.writeWebSocketError(stream, open.ConnID, code)
		server.report(err)
		return nil
	}
	defer connection.Close()
	joinIntake()
	if handshakeCtx.Err() != nil {
		return handshakeCtx.Err()
	}
	cancelHandshake()
	if err := credentials.check(); err != nil {
		return err
	}
	connection.SetReadLimit(int64(server.config.maxWSFrame))
	if err := writeProxyMetadata(stream, proxyWebSocketResponse{
		Version: proxyWireVersion, ConnID: open.ConnID, OK: true, Protocol: connection.Subprotocol(),
	}); err != nil {
		server.report(err)
		return err
	}

	operationContext := ctx
	if credentials != nil {
		operationContext = credentials.ctx
	}
	if operationContext == nil {
		operationContext = context.Background()
	}
	type relayResult struct {
		closeFrame bool
		err        error
	}
	downstream := make(chan relayResult, 1)
	upstream := make(chan relayResult, 1)
	go func() {
		downstream <- func() relayResult {
			for {
				operation, payload, err := readProxyWebSocketFrame(stream, server.config.maxWSFrame)
				if err != nil {
					return relayResult{err: err}
				}
				messageType := 0
				switch operation {
				case 1:
					messageType = websocket.TextMessage
				case 2:
					messageType = websocket.BinaryMessage
				case 8:
					messageType = websocket.CloseMessage
				case 9:
					messageType = websocket.PingMessage
				case 10:
					messageType = websocket.PongMessage
				default:
					return relayResult{err: ErrInvalidProxyServer}
				}
				if err = credentials.check(); err != nil {
					return relayResult{err: err}
				}
				err = connection.WriteMessage(messageType, payload)
				if operation == 8 || err != nil {
					return relayResult{closeFrame: operation == 8, err: err}
				}
			}
		}()
	}()
	go func() {
		upstream <- func() relayResult {
			for {
				messageType, payload, err := connection.ReadMessage()
				if err != nil {
					var closeErr *websocket.CloseError
					// An abnormal transport EOF is not a received close frame.
					if !errors.As(err, &closeErr) || closeErr.Code == websocket.CloseAbnormalClosure {
						return relayResult{err: err}
					}
					messageType = websocket.CloseMessage
					payload = proxyWebSocketClosePayload(closeErr.Code, closeErr.Text)
				}
				operation := byte(0)
				switch messageType {
				case websocket.TextMessage:
					operation = 1
				case websocket.BinaryMessage:
					operation = 2
				case websocket.CloseMessage:
					operation = 8
				case websocket.PingMessage:
					operation = 9
				case websocket.PongMessage:
					operation = 10
				default:
					continue
				}
				if err = credentials.check(); err == nil {
					err = writeProxyWebSocketFrame(stream, operation, payload, server.config.maxWSFrame)
				}
				if operation == 8 {
					// ReadMessage has already sent Gorilla's close response. End
					// that native socket while the downstream exchange stays live.
					_ = connection.Close()
				}
				if operation == 8 || err != nil {
					return relayResult{closeFrame: operation == 8 && err == nil, err: err}
				}
			}
		}()
	}()
	stop := func() {
		_ = connection.Close()
		resetStream()
	}
	failure := func(err error) error {
		if err != nil && !errors.Is(err, io.EOF) {
			server.report(err)
			return err
		}
		return nil
	}
	var fromDownstream, fromUpstream relayResult
	downstreamDone := false
	select {
	case <-operationContext.Done():
		stop()
		<-downstream
		<-upstream
		return operationContext.Err()
	case fromDownstream = <-downstream:
		downstreamDone = true
		if !fromDownstream.closeFrame || fromDownstream.err != nil && !errors.Is(fromDownstream.err, websocket.ErrCloseSent) {
			stop()
			<-upstream
			return failure(fromDownstream.err)
		}
		// A client close starts the exchange. Keep the reverse relay alive
		// until the actual upstream response or the original lifetime ends.
		select {
		case fromUpstream = <-upstream:
		case <-operationContext.Done():
			stop()
			<-upstream
			return operationContext.Err()
		}
	case fromUpstream = <-upstream:
	}
	if !fromUpstream.closeFrame {
		stop()
		if !downstreamDone {
			<-downstream
		}
		return failure(fromUpstream.err)
	}
	// The upstream Close and preceding messages may still be buffered by the
	// downstream framing owner. Its actual Close response completes the other
	// direction; an early STOP would revoke those unread application bytes.
	if !downstreamDone {
		select {
		case fromDownstream = <-downstream:
		case <-operationContext.Done():
			stop()
			<-downstream
			return operationContext.Err()
		}
	}
	// Gorilla's default close handler may already have replied to this exact
	// upstream close before the downstream close reaches its writer.
	if fromDownstream.closeFrame && errors.Is(fromDownstream.err, websocket.ErrCloseSent) {
		fromDownstream.err = nil
	}
	if !fromDownstream.closeFrame || fromDownstream.err != nil {
		stop()
	}
	return failure(fromDownstream.err)
}

func proxyWebSocketClosePayload(code int, reason string) []byte {
	if code < 0 || code > 65535 || code == 1004 || code == 1005 || code == 1006 {
		return nil
	}
	reasonBytes := []byte(reason)
	if len(reasonBytes) > 123 {
		reasonBytes = reasonBytes[:123]
		for len(reasonBytes) > 0 && !utf8.Valid(reasonBytes) {
			reasonBytes = reasonBytes[:len(reasonBytes)-1]
		}
	}
	payload := make([]byte, 2+len(reasonBytes))
	binary.BigEndian.PutUint16(payload[:2], uint16(code))
	copy(payload[2:], reasonBytes)
	return payload
}

func (server *ProxyServer) writeWebSocketError(stream io.Writer, connectionID, code string) {
	connectionID = strings.TrimSpace(connectionID)
	if connectionID == "" {
		connectionID = "unknown"
	}
	_ = writeProxyMetadata(stream, proxyWebSocketResponse{
		Version: proxyWireVersion, ConnID: connectionID, OK: false, Error: proxyStableError(code),
	})
}
