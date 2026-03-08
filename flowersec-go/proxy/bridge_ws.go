package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	"github.com/gorilla/websocket"
)

func (b *Bridge) ProxyWS(w http.ResponseWriter, r *http.Request, route StreamOpener, upgrader websocket.Upgrader) error {
	if b == nil || b.cfg == nil {
		return writeBridgeHTTPError(w, "bridge_not_configured", http.StatusInternalServerError, "bridge not configured", errors.New("missing bridge config"))
	}
	if route == nil {
		return writeBridgeHTTPError(w, "route_missing", http.StatusBadGateway, "upstream route missing", errors.New("missing route"))
	}
	if wsUpgraderCheckOriginDenied(upgrader, r) {
		return writeBridgeHTTPError(w, "browser_origin_rejected", http.StatusForbidden, "request origin not allowed", errors.New("request origin rejected"))
	}

	stream, err := route.OpenStream(r.Context(), KindWS)
	if err != nil {
		return writeBridgeHTTPError(w, "stream_open_failed", http.StatusBadGateway, "upstream connect failed", err)
	}

	connID := opaqueID(18)
	open := WSOpenMeta{
		V:       ProtocolVersion,
		ConnID:  connID,
		Path:    r.URL.RequestURI(),
		Headers: wsOpenMetaHeadersFromHTTPHeader(r.Header, &b.cfg.compiledHeaderPolicy),
	}
	if err := jsonframe.WriteJSONFrame(stream, open); err != nil {
		_ = stream.Close()
		return writeBridgeHTTPError(w, "stream_write_failed", http.StatusBadGateway, "upstream ws open failed", err)
	}

	respBytes, err := jsonframe.ReadJSONFrame(stream, b.cfg.maxJSONFrameBytes)
	if err != nil {
		_ = stream.Close()
		return writeBridgeHTTPError(w, "stream_read_failed", http.StatusBadGateway, "upstream ws open failed", err)
	}
	var resp WSOpenResp
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		_ = stream.Close()
		return writeBridgeHTTPError(w, "invalid_ws_open_resp", http.StatusBadGateway, "upstream ws open invalid", err)
	}
	if err := validateWSOpenResp(resp, connID); err != nil {
		_ = stream.Close()
		return writeBridgeHTTPError(w, "invalid_ws_open_resp", http.StatusBadGateway, "upstream ws open invalid", err)
	}
	if !resp.OK {
		_ = stream.Close()
		status, message := proxyWSErrorToStatus(resp.Error.Code)
		return writeBridgeHTTPError(w, resp.Error.Code, status, message, errors.New(resp.Error.Message))
	}

	requested := websocket.Subprotocols(r)
	if resp.Protocol != "" && !containsString(requested, resp.Protocol) {
		_ = stream.Close()
		return writeBridgeHTTPError(w, "ws_subprotocol_mismatch", http.StatusBadGateway, "ws subprotocol mismatch", errors.New("upstream selected unexpected subprotocol"))
	}

	wsUpgrader := upgrader
	if resp.Protocol != "" {
		wsUpgrader.Subprotocols = []string{resp.Protocol}
	}
	wsConn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		_ = stream.Close()
		return newBridgeError("browser_ws_upgrade_failed", http.StatusForbidden, "browser ws upgrade failed", err)
	}
	defer wsConn.Close()
	defer stream.Close()

	wsConn.SetReadLimit(int64(b.cfg.maxWSFrameBytes))

	errCh := make(chan error, 2)
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			_ = wsConn.Close()
			_ = stream.Close()
		})
	}

	go func() {
		for {
			mt, payload, err := wsConn.ReadMessage()
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
			if err := writeWSFrame(stream, op, payload, b.cfg.maxWSFrameBytes); err != nil {
				errCh <- err
				return
			}
			if op == 8 {
				errCh <- io.EOF
				return
			}
		}
	}()

	go func() {
		for {
			op, payload, err := readWSFrame(stream, b.cfg.maxWSFrameBytes)
			if err != nil {
				errCh <- err
				return
			}
			var mt int
			switch op {
			case 1:
				mt = websocket.TextMessage
			case 2:
				mt = websocket.BinaryMessage
			case 8:
				mt = websocket.CloseMessage
			case 9:
				mt = websocket.PingMessage
			case 10:
				mt = websocket.PongMessage
			default:
				continue
			}
			if err := wsConn.WriteMessage(mt, payload); err != nil {
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
	case <-r.Context().Done():
		closeAll()
		return nil
	case <-errCh:
		closeAll()
		return nil
	}
}

func validateWSOpenResp(resp WSOpenResp, connID string) error {
	if resp.V != ProtocolVersion {
		return errors.New("unsupported version")
	}
	if strings.TrimSpace(resp.ConnID) == "" {
		return errors.New("missing conn_id")
	}
	if resp.ConnID != connID {
		return errors.New("conn_id mismatch")
	}
	if resp.OK {
		return nil
	}
	if resp.Error == nil {
		return errors.New("missing error")
	}
	if strings.TrimSpace(resp.Error.Code) == "" {
		return errors.New("missing error code")
	}
	return nil
}

func proxyWSErrorToStatus(code string) (status int, message string) {
	switch code {
	case "timeout":
		return http.StatusGatewayTimeout, "upstream ws open timed out"
	case "upstream_ws_rejected", "upstream_ws_dial_failed", "canceled":
		return http.StatusBadGateway, "upstream ws open failed"
	case "invalid_ws_open_meta":
		return http.StatusBadGateway, "upstream ws open invalid"
	default:
		return http.StatusBadGateway, "upstream ws open failed"
	}
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func wsUpgraderCheckOriginDenied(upgrader websocket.Upgrader, r *http.Request) bool {
	if upgrader.CheckOrigin == nil {
		return false
	}
	return !upgrader.CheckOrigin(r)
}
