package flowersec

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

func (server *ProxyServer) serveWebSocket(ctx context.Context, incoming IncomingStream) error {
	if incoming.Stream == nil {
		server.report(ErrInvalidProxyServer)
		return ErrInvalidProxyServer
	}
	stream := incoming.Stream
	open := proxyWebSocketOpen{}
	if err := readProxyJSON(stream, server.config.maxJSONFrame, &open); err != nil {
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
		server.report(err)
		return nil
	}
	defer connection.Close()
	connection.SetReadLimit(int64(server.config.maxWSFrame))
	if err := writeProxyJSON(stream, proxyWebSocketResponse{
		Version: proxyWireVersion, ConnID: open.ConnID, OK: true, Protocol: connection.Subprotocol(),
	}); err != nil {
		server.report(err)
		return err
	}

	operationContext := ctx
	if operationContext == nil {
		operationContext = context.Background()
	}
	operationContext, cancel := context.WithCancel(operationContext)
	defer cancel()
	errorsCh := make(chan error, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			cancel()
			_ = connection.Close()
		})
	}
	go func() {
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
				if err == nil && operation == 8 {
					return
				}
			}
			if err != nil {
				errorsCh <- err
				return
			}
		}
	}()
	go func() {
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
					return
				}
			} else {
				var closeErr *websocket.CloseError
				if errors.As(err, &closeErr) {
					payload := proxyWebSocketClosePayload(closeErr.Code, closeErr.Text)
					err = writeProxyWebSocketFrame(stream, 8, payload, server.config.maxWSFrame)
					if err == nil {
						err = io.EOF
					}
				}
			}
			if err != nil {
				errorsCh <- err
				return
			}
		}
	}()
	select {
	case <-operationContext.Done():
		closeBoth()
		return operationContext.Err()
	case err := <-errorsCh:
		closeBoth()
		if err != nil && !errors.Is(err, io.EOF) {
			server.report(err)
			return err
		}
		return nil
	}
}

func proxyWebSocketClosePayload(code int, reason string) []byte {
	if code < 0 || code > 65535 || code == 1004 || code == 1005 || code == 1006 {
		return nil
	}
	reasonBytes := []byte(reason)
	if len(reasonBytes) > 123 {
		reasonBytes = reasonBytes[:123]
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
