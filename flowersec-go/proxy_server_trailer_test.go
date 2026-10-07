package flowersec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestProxyServerRejectsHiddenContentCoding(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Connection", "content-encoding, close")
		_, _ = io.WriteString(w, "coded")
	}))
	defer upstream.Close()
	server, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handlers := &StreamHandlerPlanConfig{}
	if err := server.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); err != nil {
		t.Fatal(err)
	}
	client := serveProxyTestStream(t, server, handlers, proxyHTTPStreamKind)
	if err := writeProxyMetadata(client, proxyHTTPRequest{Version: proxyWireVersion, RequestID: "hidden-coding", Method: "GET", Path: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyTerminator(client); err != nil {
		t.Fatal(err)
	}
	var response proxyHTTPResponse
	if err := readProxyMetadata(client, 1<<20, &response); err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Error == nil || response.Error.Code != "upstream_request_failed" {
		t.Fatalf("hidden content coding was published: %+v", response)
	}
}

func TestProxyServerNativeTrailersAndOriginForm(t *testing.T) {
	for _, body := range []string{"", "request-body"} {
		t.Run(fmt.Sprintf("bytes=%d", len(body)), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != "//other.example/a?" {
					t.Errorf("origin-form target rewritten: %q", r.RequestURI)
				}
				got, err := io.ReadAll(r.Body)
				if err != nil || string(got) != body {
					t.Errorf("body: %q, %v", got, err)
				}
				if got := r.Trailer.Values("X-Check"); !reflect.DeepEqual(got, []string{"first", "\xe9"}) {
					t.Errorf("request trailers: %q", got)
				}
				w.Header().Set("Trailer", "X-Check")
				_, _ = io.WriteString(w, "response")
				w.Header().Add("X-Check", "one")
				w.Header().Add("X-Check", "\xff")
			}))
			defer upstream.Close()
			proxy, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL, ExtraRequestHeaders: []string{"x-check"}, ExtraResponseHeaders: []string{"x-check"}})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			handlers := &StreamHandlerPlanConfig{}
			if err := proxy.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); err != nil {
				t.Fatal(err)
			}
			client := serveProxyTestStream(t, proxy, handlers, proxyHTTPStreamKind)
			if err := writeProxyMetadata(client, proxyHTTPRequest{Version: proxyWireVersion, RequestID: "trailers", Method: "POST", Path: "//other.example/a?", Headers: []proxyHeader{{Name: "content-length", Value: fmt.Sprint(len(body))}, {Name: "connection", Value: "content-length"}}}); err != nil {
				t.Fatal(err)
			}
			var total int64
			if body != "" {
				if err := writeProxyChunk(client, []byte(body), 1024, &total, 1024); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeProxyBodyEnd(client, []proxyHeader{{Name: "x-check", Value: "first"}, {Name: "x-check", Value: "\xe9"}}); err != nil {
				t.Fatal(err)
			}
			var meta proxyHTTPResponse
			if err := readProxyMetadata(client, 1<<20, &meta); err != nil {
				t.Fatal(err)
			}
			if !meta.OK {
				t.Fatalf("response: %+v", meta)
			}
			total = 0
			var result []byte
			for {
				chunk, trailers, done, err := readProxyBodyPart(client, 1024, &total, 1024, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				result = append(result, chunk...)
				if done {
					want := []proxyHeader{{Name: "x-check", Value: "one"}, {Name: "x-check", Value: "\xff"}}
					if !reflect.DeepEqual(trailers, want) {
						t.Fatalf("response trailers: %+v", trailers)
					}
					break
				}
			}
			if string(result) != "response" {
				t.Fatalf("response body: %q", result)
			}
		})
	}
}

func TestProxyRegistrationRequiresOriginalAuthorization(t *testing.T) {
	server, err := NewProxyServer(ProxyServerOptions{Upstream: "http://127.0.0.1:1", UpstreamOrigin: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if _, err := server.StreamHandlers(nil); err == nil {
		t.Fatal("missing authorization accepted")
	}
	var calls int
	registrations, err := server.StreamHandlers(func(_ context.Context, binding any, metadata []byte) error {
		calls++
		if binding != "identity" || string(metadata) != "frozen" {
			t.Fatal("original binding lost")
		}
		return nil
	})
	if err != nil || len(registrations) != 2 {
		t.Fatalf("registrations: %v", err)
	}
	for _, registration := range registrations {
		if err := registration.AuthorizeOpen(context.Background(), "identity", []byte("frozen")); err != nil {
			t.Fatal(err)
		}
		if registration.WorkClass != WorkResident {
			t.Fatal("proxy bypassed resident executor")
		}
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := registrations[0].AuthorizeOpen(context.Background(), "identity", nil); err == nil || calls != 2 {
		t.Fatal("closed proxy invoked authorization")
	}
}
