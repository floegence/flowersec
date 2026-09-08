package flowersec

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type httpTestByteStream struct{ net.Conn }

func (s httpTestByteStream) Kind() string                 { return "test/http" }
func (s httpTestByteStream) TerminalError() *SessionError { return nil }
func (s httpTestByteStream) CloseWrite() error            { return nil }
func (s httpTestByteStream) Reset() error                 { return s.Close() }

func TestServeHTTPStreamKeepAliveAndCancellation(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeHTTPStream(ctx, httpTestByteStream{server}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Set-Cookie", "a=1")
			w.Header().Add("Set-Cookie", "b=2")
			_, _ = io.Copy(w, r.Body)
		}), HTTPStreamOptions{})
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(client)
	for i := 0; i < 2; i++ {
		_, err := io.WriteString(client, "POST /echo HTTP/1.1\r\nHost: test\r\nContent-Length: 3\r\n\r\nabc")
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != "abc" || len(response.Cookies()) != 2 {
			t.Fatalf("response %q %v", body, err)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not close")
	}
}

func TestServeHTTPStreamUpgradeAndHeaderDeadline(t *testing.T) {
	t.Run("upgrade", func(t *testing.T) {
		server, client := net.Pipe()
		defer client.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- ServeHTTPStream(ctx, httpTestByteStream{server}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
				_ = rw.Flush()
				_, _ = io.Copy(conn, rw)
			}), HTTPStreamOptions{})
		}()
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		go func() {
			_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\nhead")
		}()
		r := bufio.NewReader(client)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "\r\n" {
				break
			}
		}
		body := make([]byte, 4)
		if _, err := io.ReadFull(r, body); err != nil || string(body) != "head" {
			t.Fatalf("head %q %v", body, err)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("hijacked connection survived cancellation")
		}
	})
	t.Run("header timeout", func(t *testing.T) {
		server, client := net.Pipe()
		defer client.Close()
		done := make(chan error, 1)
		go func() {
			done <- ServeHTTPStream(context.Background(), httpTestByteStream{server}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("incomplete headers admitted") }), HTTPStreamOptions{ReadHeaderTimeout: 20 * time.Millisecond})
		}()
		_, _ = io.WriteString(client, "GET / HTTP/1.1\r\n"+strings.Repeat("X", 10))
		go func() { _, _ = io.Copy(io.Discard, client) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("incomplete headers stayed open")
		}
	})
}
