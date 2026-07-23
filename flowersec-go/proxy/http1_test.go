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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/framing/jsonframe"
)

func TestHTTP1Handler_GET_EndToEnd(t *testing.T) {
	type seen struct {
		method string
		path   string
		auth   string
		origin string
		host   string
		proto  string
	}
	seenCh := make(chan seen, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- seen{
			method: r.Method,
			path:   r.URL.Path,
			auth:   r.Header.Get("Authorization"),
			origin: r.Header.Get("Origin"),
			host:   r.Host,
			proto:  r.Header.Get("X-Forwarded-Proto"),
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
			{Name: "origin", Value: "https://gateway.example.com"},
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
	if s.origin != "https://gateway.example.com" {
		t.Fatalf("unexpected upstream origin: %q", s.origin)
	}
	if s.host == "" {
		t.Fatalf("expected upstream host to be set")
	}
}

func TestHTTP1Handler_GET_DoesNotFollowRedirects(t *testing.T) {
	tests := []struct {
		name        string
		crossOrigin bool
	}{
		{name: "same origin"},
		{name: "cross origin", crossOrigin: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			var redirectTargetHits atomic.Int32

			redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirectTargetHits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer redirectTarget.Close()

			var location string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamHits.Add(1)
				if r.URL.Path == "/redirected" {
					redirectTargetHits.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.Header().Set("Location", location)
				w.WriteHeader(http.StatusFound)
			}))
			defer upstream.Close()

			location = upstream.URL + "/redirected"
			if tt.crossOrigin {
				location = redirectTarget.URL + "/redirected"
			}

			cfg, err := compileOptions(Options{
				Upstream:       upstream.URL,
				UpstreamOrigin: upstream.URL,
			})
			if err != nil {
				t.Fatalf("compileOptions: %v", err)
			}

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			go http1Handler(cfg)(context.Background(), serverConn)

			reqMeta := HTTPRequestMeta{
				V:         ProtocolVersion,
				RequestID: "redirect",
				Method:    http.MethodGet,
				Path:      "/start",
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
			if !respMeta.OK || respMeta.Status != http.StatusFound {
				t.Fatalf("unexpected resp meta: %#v", respMeta)
			}
			var gotLocation string
			for _, header := range respMeta.Headers {
				if header.Name == "location" {
					gotLocation = header.Value
					break
				}
			}
			if gotLocation != location {
				t.Fatalf("unexpected location header: got %q, want %q", gotLocation, location)
			}

			var readBytes int64
			for {
				_, done, err := readChunkFrame(clientConn, cfg.maxChunkBytes, cfg.maxBodyBytes, &readBytes)
				if err != nil {
					t.Fatalf("read body chunk: %v", err)
				}
				if done {
					break
				}
			}

			if got := upstreamHits.Load(); got != 1 {
				t.Fatalf("unexpected upstream request count: got %d, want 1", got)
			}
			if got := redirectTargetHits.Load(); got != 0 {
				t.Fatalf("redirect target was requested %d times", got)
			}
		})
	}
}

func TestHTTP1Handler_GET_UsesExternalOriginWhenBrowserOriginIsAbsent(t *testing.T) {
	type seen struct {
		host   string
		proto  string
		origin string
		path   string
	}
	seenCh := make(chan seen, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- seen{
			host:   r.Host,
			proto:  r.Header.Get("X-Forwarded-Proto"),
			origin: r.Header.Get("Origin"),
			path:   r.URL.Path,
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "env")
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
		V:              ProtocolVersion,
		RequestID:      "r-ext",
		Method:         "GET",
		Path:           "/_redeven_proxy/env/",
		Headers:        []Header{{Name: "accept", Value: "text/html"}},
		ExternalOrigin: "https://env-123.example.com",
	}
	if err := jsonframe.WriteJSONFrame(clientConn, reqMeta); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	if err := writeChunkTerminator(clientConn); err != nil {
		t.Fatalf("write terminator: %v", err)
	}

	if _, err := jsonframe.ReadJSONFrame(clientConn, cfg.maxJSONFrameBytes); err != nil {
		t.Fatalf("read resp meta: %v", err)
	}
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

	s := <-seenCh
	if s.path != "/_redeven_proxy/env/" {
		t.Fatalf("unexpected upstream path: %q", s.path)
	}
	if s.origin != "" {
		t.Fatalf("expected upstream origin to stay empty, got %q", s.origin)
	}
	if s.host != "env-123.example.com" {
		t.Fatalf("unexpected upstream host: %q", s.host)
	}
	if s.proto != "https" {
		t.Fatalf("unexpected upstream proto: %q", s.proto)
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

func TestHTTP1Handler_StreamsRequestAndResponseBeforeTermination(t *testing.T) {
	requestFirstChunk := make(chan struct{})
	allowRequestEnd := make(chan struct{})
	responseFirstChunk := make(chan struct{})
	allowResponseEnd := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, first); err != nil {
			t.Errorf("read first request chunk: %v", err)
			return
		}
		if string(first) != "first" {
			t.Errorf("unexpected first request chunk: %q", string(first))
			return
		}
		close(requestFirstChunk)
		<-allowRequestEnd
		if rest, err := io.ReadAll(r.Body); err != nil || string(rest) != "last" {
			t.Errorf("unexpected remaining request body: body=%q err=%v", string(rest), err)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("head"))
		w.(http.Flusher).Flush()
		close(responseFirstChunk)
		<-allowResponseEnd
		_, _ = w.Write([]byte("tail"))
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

	if err := jsonframe.WriteJSONFrame(clientConn, HTTPRequestMeta{
		V: ProtocolVersion, RequestID: "streaming", Method: http.MethodPost, Path: "/",
	}); err != nil {
		t.Fatalf("write request metadata: %v", err)
	}
	if err := writeChunkFrame(clientConn, []byte("first"), cfg.maxChunkBytes, cfg.maxBodyBytes, nil); err != nil {
		t.Fatalf("write first request chunk: %v", err)
	}
	select {
	case <-requestFirstChunk:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive the first request chunk before the terminator")
	}
	close(allowRequestEnd)
	if err := writeChunkFrame(clientConn, []byte("last"), cfg.maxChunkBytes, cfg.maxBodyBytes, nil); err != nil {
		t.Fatalf("write final request chunk: %v", err)
	}
	if err := writeChunkTerminator(clientConn); err != nil {
		t.Fatalf("write request terminator: %v", err)
	}

	if _, err := jsonframe.ReadJSONFrame(clientConn, cfg.maxJSONFrameBytes); err != nil {
		t.Fatalf("read response metadata: %v", err)
	}
	select {
	case <-responseFirstChunk:
	case <-time.After(time.Second):
		t.Fatal("upstream did not flush the first response chunk")
	}
	var readBytes int64
	chunk, done, err := readChunkFrame(clientConn, cfg.maxChunkBytes, cfg.maxBodyBytes, &readBytes)
	if err != nil {
		t.Fatalf("read first response chunk: %v", err)
	}
	if done || string(chunk) != "head" {
		t.Fatalf("unexpected first response chunk: done=%v body=%q", done, string(chunk))
	}
	close(allowResponseEnd)
	chunk, done, err = readChunkFrame(clientConn, cfg.maxChunkBytes, cfg.maxBodyBytes, &readBytes)
	if err != nil {
		t.Fatalf("read final response chunk: %v", err)
	}
	if done || string(chunk) != "tail" {
		t.Fatalf("unexpected final response chunk: done=%v body=%q", done, string(chunk))
	}
	if _, done, err := readChunkFrame(clientConn, cfg.maxChunkBytes, cfg.maxBodyBytes, &readBytes); err != nil || !done {
		t.Fatalf("read response terminator: done=%v err=%v", done, err)
	}
}

func TestHTTP1Handler_ResetsUnknownLengthResponseOverflowAfterMetadata(t *testing.T) {
	allowOverflow := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ab"))
		w.(http.Flusher).Flush()
		<-allowOverflow
		_, _ = w.Write([]byte("cd"))
	}))
	defer up.Close()

	cfg, err := compileOptions(Options{
		Upstream:       up.URL,
		UpstreamOrigin: up.URL,
		ContractOptions: ContractOptions{
			MaxChunkBytes: 2,
			MaxBodyBytes:  3,
		},
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	stream := &resetRecordingStream{ReadWriteCloser: serverConn}
	doneCh := make(chan struct{})
	go func() {
		http1Handler(cfg)(context.Background(), stream)
		close(doneCh)
	}()
	defer clientConn.Close()

	if err := jsonframe.WriteJSONFrame(clientConn, HTTPRequestMeta{
		V: ProtocolVersion, RequestID: "overflow", Method: http.MethodGet, Path: "/",
	}); err != nil {
		t.Fatalf("write request metadata: %v", err)
	}
	if err := writeChunkTerminator(clientConn); err != nil {
		t.Fatalf("write request terminator: %v", err)
	}
	if _, err := jsonframe.ReadJSONFrame(clientConn, cfg.maxJSONFrameBytes); err != nil {
		t.Fatalf("read response metadata: %v", err)
	}
	var readBytes int64
	chunk, done, err := readChunkFrame(clientConn, cfg.maxChunkBytes, cfg.maxBodyBytes, &readBytes)
	if err != nil {
		t.Fatalf("read first response chunk: %v", err)
	}
	if done || string(chunk) != "ab" {
		t.Fatalf("unexpected first response chunk: done=%v body=%q", done, string(chunk))
	}
	close(allowOverflow)
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("handler did not terminate after response overflow")
	}
	if !stream.reset.Load() {
		t.Fatal("response overflow after metadata did not reset the stream")
	}
}

type resetRecordingStream struct {
	io.ReadWriteCloser
	reset     atomic.Bool
	resetOnce sync.Once
}

func (s *resetRecordingStream) Reset() error {
	s.reset.Store(true)
	var err error
	s.resetOnce.Do(func() { err = s.Close() })
	return err
}

func TestHTTP1Handler_InvalidMetaFrameTooLarge_ReturnsErrorMeta(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	cfg, err := compileOptions(Options{
		Upstream:       up.URL,
		UpstreamOrigin: up.URL,
		ContractOptions: ContractOptions{
			MaxJSONFrameBytes: 16,
		},
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
