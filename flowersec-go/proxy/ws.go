package proxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	"github.com/gorilla/websocket"
)

func wsHandler(cfg *compiledOptions) func(ctx context.Context, stream io.ReadWriteCloser) {
	dialer := &websocket.Dialer{
		Proxy:             nil,
		HandshakeTimeout:  10 * time.Second,
		EnableCompression: false,
	}

	return func(ctx context.Context, stream io.ReadWriteCloser) {
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		metaBytes, err := jsonframe.ReadJSONFrame(stream, cfg.maxJSONFrameBytes)
		if err != nil {
			_ = writeWSOpenError(stream, "", "invalid_ws_open_meta", err)
			return
		}
		var meta WSOpenMeta
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			_ = writeWSOpenError(stream, "", "invalid_ws_open_meta", err)
			return
		}
		if meta.V != ProtocolVersion {
			_ = writeWSOpenError(stream, meta.ConnID, "invalid_ws_open_meta", fmt.Errorf("unsupported v: %d", meta.V))
			return
		}
		meta.ConnID = strings.TrimSpace(meta.ConnID)
		if meta.ConnID == "" {
			_ = writeWSOpenError(stream, "", "invalid_ws_open_meta", errors.New("missing conn_id"))
			return
		}
		parsedPath, err := parseRequestPath(meta.Path)
		if err != nil {
			_ = writeWSOpenError(stream, meta.ConnID, "invalid_ws_open_meta", fmt.Errorf("invalid path: %w", err))
			return
		}

		upURL := *cfg.upstream
		switch upURL.Scheme {
		case "http":
			upURL.Scheme = "ws"
		case "https":
			upURL.Scheme = "wss"
		default:
			_ = writeWSOpenError(stream, meta.ConnID, "upstream_ws_dial_failed", fmt.Errorf("unexpected upstream scheme: %q", upURL.Scheme))
			return
		}
		upURL.Path = parsedPath.Path
		upURL.RawQuery = parsedPath.RawQuery
		upURL.Fragment = ""

		h := filterWSOpenHeaders(meta.Headers, cfg)
		h.Set("Origin", cfg.upstreamOrigin)

		conn, resp, err := dialer.DialContext(ctx, upURL.String(), h)
		if err != nil {
			code := "upstream_ws_dial_failed"
			if resp != nil {
				code = "upstream_ws_rejected"
			} else if errors.Is(err, context.DeadlineExceeded) {
				code = "timeout"
			} else if errors.Is(err, context.Canceled) {
				code = "canceled"
			}
			_ = writeWSOpenError(stream, meta.ConnID, code, err)
			return
		}
		defer conn.Close()
		conn.SetReadLimit(int64(cfg.maxWSFrameBytes))

		if err := jsonframe.WriteJSONFrame(stream, WSOpenResp{
			V:        ProtocolVersion,
			ConnID:   meta.ConnID,
			OK:       true,
			Protocol: conn.Subprotocol(),
		}); err != nil {
			return
		}

		errCh := make(chan error, 2)
		var once sync.Once
		closeAll := func() {
			once.Do(func() {
				cancel()
				_ = conn.Close()
				_ = stream.Close()
			})
		}

		// Stream -> upstream WS.
		go func() {
			for {
				op, payload, err := readWSFrame(stream, cfg.maxWSFrameBytes)
				if err != nil {
					errCh <- err
					return
				}
				switch op {
				case 1:
					err = conn.WriteMessage(websocket.TextMessage, payload)
				case 2:
					err = conn.WriteMessage(websocket.BinaryMessage, payload)
				case 8:
					err = conn.WriteMessage(websocket.CloseMessage, payload)
				case 9:
					err = conn.WriteMessage(websocket.PingMessage, payload)
				case 10:
					err = conn.WriteMessage(websocket.PongMessage, payload)
				default:
					err = errors.New("invalid ws op")
				}
				if err != nil {
					errCh <- err
					return
				}
				if op == 8 {
					errCh <- io.EOF
					return
				}
			}
		}()

		// Upstream WS -> stream.
		go func() {
			for {
				mt, payload, err := conn.ReadMessage()
				if err != nil {
					errCh <- err
					return
				}
				var op byte
				switch mt {
				case websocket.TextMessage:
					op = 1
				case websocket.BinaryMessage:
					op = 2
				case websocket.CloseMessage:
					op = 8
				case websocket.PingMessage:
					op = 9
				case websocket.PongMessage:
					op = 10
				default:
					continue
				}
				if err := writeWSFrame(stream, op, payload, cfg.maxWSFrameBytes); err != nil {
					errCh <- err
					return
				}
				if op == 8 {
					errCh <- io.EOF
					return
				}
			}
		}()

		select {
		case <-ctx.Done():
			closeAll()
			return
		case <-errCh:
			closeAll()
			return
		}
	}
}

func writeWSOpenError(w io.Writer, connID string, code string, err error) error {
	connID = strings.TrimSpace(connID)
	if connID == "" {
		connID = "unknown"
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	withWriteDeadline(w, errorWriteTimeout, func() {
		_ = jsonframe.WriteJSONFrame(w, WSOpenResp{
			V:      ProtocolVersion,
			ConnID: connID,
			OK:     false,
			Error:  &Error{Code: code, Message: msg},
		})
	})
	return nil
}

func readWSFrame(r io.Reader, maxPayload int) (op byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	op = hdr[0]
	n := int(binary.BigEndian.Uint32(hdr[1:5]))
	if n < 0 || (maxPayload > 0 && n > maxPayload) {
		return 0, nil, ErrChunkTooLarge
	}
	if n == 0 {
		return op, nil, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return op, b, nil
}

func writeWSFrame(w io.Writer, op byte, payload []byte, maxPayload int) error {
	if maxPayload > 0 && len(payload) > maxPayload {
		return ErrChunkTooLarge
	}
	var hdr [5]byte
	hdr[0] = op
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}
