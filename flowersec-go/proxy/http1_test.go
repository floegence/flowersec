package proxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
)

func TestHTTP1Handler_GET_EndToEnd(t *testing.T) {
	type seen struct {
		method string
		path   string
		auth   string
		origin string
	}
	seenCh := make(chan seen, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- seen{
			method: r.Method,
			path:   r.URL.Path,
			auth:   r.Header.Get("Authorization"),
			origin: r.Header.Get("Origin"),
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "world")
	}))
	defer up.Close()

	cfg, err := compileOptions(Options{
		Upstream:       up.URL,
		UpstreamOrigin: up.URL,
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go http1Handler(cfg)(context.Background(), serverConn)

	reqMeta := HTTPRequestMeta{
		V:         ProtocolVersion,
		RequestID: "r1",
		Method:    "GET",
		Path:      "/hello",
		Headers: []Header{
			{Name: "accept", Value: "text/plain"},
			{Name: "authorization", Value: "Bearer secret"},
		},
	}
	if err := jsonframe.WriteJSONFrame(clientConn, reqMeta); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	if err := writeChunkTerminator(clientConn); err != nil {
		t.Fatalf("write terminator: %v", err)
	}

	b, err := jsonframe.ReadJSONFrame(clientConn, cfg.maxJSONFrameBytes)
	if err != nil {
		t.Fatalf("read resp meta: %v", err)
	}
	var respMeta HTTPResponseMeta
	if err := json.Unmarshal(b, &respMeta); err != nil {
		t.Fatalf("unmarshal resp meta: %v", err)
	}
	if !respMeta.OK || respMeta.Status != 200 {
		t.Fatalf("unexpected resp meta: %#v", respMeta)
	}
	var body strings.Builder
	var readBytes int64
	for {
		ch, done, err := readChunkFrame(clientConn, cfg.maxChunkBytes, cfg.maxBodyBytes, &readBytes)
		if err != nil {
			t.Fatalf("read body chunk: %v", err)
		}
		if done {
			break
		}
		body.Write(ch)
	}
	if body.String() != "world" {
		t.Fatalf("unexpected body: %q", body.String())
	}

	s := <-seenCh
	if s.method != http.MethodGet {
		t.Fatalf("unexpected upstream method: %q", s.method)
	}
	if s.path != "/hello" {
		t.Fatalf("unexpected upstream path: %q", s.path)
	}
	if s.auth != "" {
		t.Fatalf("expected Authorization to be filtered, got %q", s.auth)
	}
	if s.origin == "" {
		t.Fatalf("expected Origin to be injected")
	}
}

func TestHTTP1Handler_POST_EndToEnd(t *testing.T) {
	bodyCh := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyCh <- string(b)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()

	cfg, err := compileOptions(Options{
		Upstream:       up.URL,
		UpstreamOrigin: up.URL,
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go http1Handler(cfg)(context.Background(), serverConn)

	reqMeta := HTTPRequestMeta{
		V:         ProtocolVersion,
		RequestID: "r2",
		Method:    "POST",
		Path:      "/",
		Headers: []Header{
			{Name: "content-type", Value: "application/octet-stream"},
		},
	}
	if err := jsonframe.WriteJSONFrame(clientConn, reqMeta); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	if err := writeChunkFrame(clientConn, []byte("a"), cfg.maxChunkBytes, cfg.maxBodyBytes, nil); err != nil {
		t.Fatalf("write chunk: %v", err)
	}
	if err := writeChunkFrame(clientConn, []byte("b"), cfg.maxChunkBytes, cfg.maxBodyBytes, nil); err != nil {
		t.Fatalf("write chunk: %v", err)
	}
	if err := writeChunkTerminator(clientConn); err != nil {
		t.Fatalf("write terminator: %v", err)
	}

	_, err = jsonframe.ReadJSONFrame(clientConn, cfg.maxJSONFrameBytes)
	if err != nil {
		t.Fatalf("read resp meta: %v", err)
	}
	// Drain response body to avoid leaking goroutines.
	var tmp int64
	for {
		_, done, err := readChunkFrame(clientConn, cfg.maxChunkBytes, cfg.maxBodyBytes, &tmp)
		if err != nil {
			t.Fatalf("read body chunk: %v", err)
		}
		if done {
			break
		}
	}

	if got := <-bodyCh; got != "ab" {
		t.Fatalf("unexpected upstream body: %q", got)
	}
}

func TestHTTP1Handler_InvalidMetaFrameTooLarge_ReturnsErrorMeta(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	cfg, err := compileOptions(Options{
		Upstream:          up.URL,
		UpstreamOrigin:    up.URL,
		MaxJSONFrameBytes: 16,
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go http1Handler(cfg)(context.Background(), serverConn)

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(cfg.maxJSONFrameBytes+1))
	if _, err := clientConn.Write(hdr[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	b, err := jsonframe.ReadJSONFrame(clientConn, jsonframe.DefaultMaxJSONFrameBytes)
	if err != nil {
		t.Fatalf("read resp meta: %v", err)
	}
	var respMeta HTTPResponseMeta
	if err := json.Unmarshal(b, &respMeta); err != nil {
		t.Fatalf("unmarshal resp meta: %v", err)
	}
	if respMeta.OK || respMeta.Error == nil || respMeta.Error.Code != "invalid_request_meta" {
		t.Fatalf("unexpected resp meta: %#v", respMeta)
	}

	// Drain the response body terminator.
	var tmp int64
	_, done, err := readChunkFrame(clientConn, cfg.maxChunkBytes, cfg.maxBodyBytes, &tmp)
	if err != nil {
		t.Fatalf("read terminator: %v", err)
	}
	if !done {
		t.Fatalf("expected body terminator")
	}
}
