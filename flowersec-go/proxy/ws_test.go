package proxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	"github.com/gorilla/websocket"
)

func TestWSHandler_Echo(t *testing.T) {
	originCh := make(chan string, 1)
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case originCh <- r.Header.Get("Origin"):
		default:
		}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.TextMessage || mt == websocket.BinaryMessage {
				_ = c.WriteMessage(mt, msg)
			}
			if mt == websocket.CloseMessage {
				return
			}
		}
	}))
	defer up.Close()

	cfg, err := compileOptions(Options{
		Upstream:       up.URL,
		UpstreamOrigin: "http://127.0.0.1:5173",
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go wsHandler(cfg)(context.Background(), serverConn)

	open := WSOpenMeta{
		V:      ProtocolVersion,
		ConnID: "c1",
		Path:   "/",
		Headers: []Header{
			{Name: "sec-websocket-protocol", Value: "demo"},
		},
	}
	if err := jsonframe.WriteJSONFrame(clientConn, open); err != nil {
		t.Fatalf("write open meta: %v", err)
	}

	b, err := jsonframe.ReadJSONFrame(clientConn, cfg.maxJSONFrameBytes)
	if err != nil {
		t.Fatalf("read open resp: %v", err)
	}
	var resp WSOpenResp
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("unmarshal open resp: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok, got %#v", resp)
	}

	if err := writeWSFrame(clientConn, 1, []byte("hello"), cfg.maxWSFrameBytes); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}
	op, payload, err := readWSFrame(clientConn, cfg.maxWSFrameBytes)
	if err != nil {
		t.Fatalf("read ws frame: %v", err)
	}
	if op != 1 || string(payload) != "hello" {
		t.Fatalf("unexpected echo frame: op=%d payload=%q", op, string(payload))
	}

	// Close gracefully.
	_ = writeWSFrame(clientConn, 8, []byte{}, cfg.maxWSFrameBytes)

	select {
	case got := <-originCh:
		if got != "http://127.0.0.1:5173" {
			t.Fatalf("unexpected upstream Origin: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for upstream origin")
	}
}

func TestReadWSFrame_RejectsOversizedPayload(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	go func() {
		var hdr [5]byte
		hdr[0] = 2
		binary.BigEndian.PutUint32(hdr[1:5], 8)
		_, _ = pw.Write(hdr[:])
		_, _ = pw.Write(make([]byte, 8))
		_ = pw.Close()
	}()

	_, _, err := readWSFrame(pr, 4)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestWSHandler_InvalidMetaFrameTooLarge_ReturnsErrorResp(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r
		_, _ = upgrader.Upgrade(w, r, nil)
	}))
	defer up.Close()

	cfg, err := compileOptions(Options{
		Upstream:          up.URL,
		UpstreamOrigin:    "http://127.0.0.1:5173",
		MaxJSONFrameBytes: 16,
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go wsHandler(cfg)(context.Background(), serverConn)

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(cfg.maxJSONFrameBytes+1))
	if _, err := clientConn.Write(hdr[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	b, err := jsonframe.ReadJSONFrame(clientConn, jsonframe.DefaultMaxJSONFrameBytes)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	var resp WSOpenResp
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	if resp.OK || resp.Error == nil || resp.Error.Code != "invalid_ws_open_meta" {
		t.Fatalf("unexpected resp: %#v", resp)
	}
}
