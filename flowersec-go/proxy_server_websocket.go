package flowersec

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

func (server *ProxyServer) serveWebSocket(ctx context.Context, incoming IncomingStream) proxyResult {
	if incoming.Stream == nil {
		return proxyResult{diagnostic: ErrInvalidProxyServer, streamErr: ErrInvalidProxyServer}
	}
	stream := incoming.Stream
	ctx, cancelOperation := context.WithCancel(ctx)
	defer cancelOperation()
	resetStream := sync.OnceFunc(func() { _ = stream.Reset() })
	resetDone := make(chan struct{})
	stopReset := context.AfterFunc(ctx, func() {
		defer close(resetDone)
		resetStream()
	})
	defer func() {
		if !stopReset() {
			<-resetDone
		}
	}()
	intake := time.AfterFunc(server.config.maxTimeout, cancelOperation)
	defer intake.Stop()
	open := proxyWebSocketOpen{}
	if err := readProxyJSON(stream, server.config.maxJSONFrame, &open); err != nil {
		server.writeWebSocketError(stream, "unknown", "invalid_ws_open_meta")
		return proxyResult{diagnostic: err}
	}
	open.ConnID = strings.TrimSpace(open.ConnID)
	path, err := parseProxyPath(open.Path)
	if open.Version != proxyWireVersion || open.ConnID == "" || err != nil {
		server.writeWebSocketError(stream, open.ConnID, "invalid_ws_open_meta")
		return proxyResult{diagnostic: ErrInvalidProxyServer}
	}
	target := *server.config.upstream
	if target.Scheme == "http" {
		target.Scheme = "ws"
	} else {
		target.Scheme = "wss"
	}
	target.Path, target.RawPath, target.RawQuery, target.Fragment = path.Path, path.RawPath, path.RawQuery, ""
	headers := proxyWebSocketHeaders(open.Headers, server.config)
	headers.Set("Origin", server.config.upstreamOrigin)
	connection, response, err := server.wsDialer.DialContext(ctx, target.String(), headers)
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
		return proxyResult{diagnostic: err}
	}
	defer connection.Close()
	connection.SetReadLimit(int64(server.config.maxWSFrame))
	if err := writeProxyJSON(stream, proxyWebSocketResponse{
		Version: proxyWireVersion, ConnID: open.ConnID, OK: true, Protocol: connection.Subprotocol(),
	}); err != nil {
		return proxyResult{diagnostic: err, streamErr: err}
	}

	intake.Stop()
	operationContext, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			cancel()
			_ = connection.Close()
			resetStream()
		})
	}
	go func() {
		errorsCh <- func() error {
			for {
				operation, payload, err := readProxyWebSocketFrame(stream, server.config.maxWSFrame)
				if err == nil {
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
						err = ErrInvalidProxyServer
					}
					if err == nil {
						err = connection.WriteMessage(messageType, payload)
					}
					if operation == 8 && (err == nil || errors.Is(err, websocket.ErrCloseSent)) {
						return nil
					}
				}
				if err != nil {
					return err
				}
			}
		}()
	}()
	go func() {
		errorsCh <- func() error {
			for {
				messageType, payload, err := connection.ReadMessage()
				operation := byte(0)
				if err == nil {
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
					err = writeProxyWebSocketFrame(stream, operation, payload, server.config.maxWSFrame)
					if err == nil && operation == 8 {
						return nil
					}
				} else {
					var closeErr *websocket.CloseError
					if errors.As(err, &closeErr) && closeErr.Code != websocket.CloseAbnormalClosure {
						payload := proxyWebSocketClosePayload(closeErr.Code, closeErr.Text)
						err = writeProxyWebSocketFrame(stream, 8, payload, server.config.maxWSFrame)
						return err
					}
				}
				if err != nil {
					return err
				}
			}
		}()
	}()
	select {
	case <-operationContext.Done():
		closeBoth()
		<-errorsCh
		<-errorsCh
		return proxyResult{streamErr: operationContext.Err()}
	case err := <-errorsCh:
		if err == nil {
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			select {
			case err = <-errorsCh:
				if err != nil {
					closeBoth()
				}
				return proxyResult{streamErr: err}
			case <-operationContext.Done():
				err = operationContext.Err()
			case <-timer.C:
				err = context.DeadlineExceeded
			}
		}
		closeBoth()
		<-errorsCh
		if err != nil && !errors.Is(err, io.EOF) {
			return proxyResult{diagnostic: err, streamErr: err}
		}
		return proxyResult{}
	}
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
	_ = writeProxyJSON(stream, proxyWebSocketResponse{
		Version: proxyWireVersion, ConnID: connectionID, OK: false, Error: proxyStableError(code),
	})
}
