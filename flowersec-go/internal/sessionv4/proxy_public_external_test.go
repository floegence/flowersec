package sessionv4_test

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"testing"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func TestPublicProxyRunsOnV4OriginalStreamOwner(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "//fixed-upstream/a?" {
			t.Errorf("target = %q", r.RequestURI)
		}
		_, _ = w.Write([]byte("v4-proxy"))
	}))
	defer upstream.Close()
	server, err := fs.NewProxyServer(fs.ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL, MaxConcurrentStreams: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	registrations, err := server.V4StreamHandlers(func(_ context.Context, binding any, metadata []byte) error {
		if binding != 1 || string(metadata) != "proxy-test" {
			t.Error("unauthenticated application projection")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, ctx := sessionv4.PublicProxyTestStream(t, registrations[0])
	write := func(value any) {
		t.Helper()
		bytes, err := protocolv4.EncodeProxyMetadata(value)
		if err != nil {
			t.Fatal(err)
		}
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(bytes)))
		if _, err := owner.WriteAll(ctx, prefix[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.WriteAll(ctx, bytes); err != nil {
			t.Fatal(err)
		}
	}
	write(protocolv4.ProxyHTTPRequest{Version: 2, RequestID: "actual-v4", Method: "GET", Path: "//fixed-upstream/a?"})
	if _, err := owner.WriteAll(ctx, []byte{0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	write(protocolv4.ProxyBodyEnd{Version: 2})
	if err := owner.CloseWrite(ctx); err != nil {
		t.Fatal(err)
	}
	read := func(size int) []byte {
		t.Helper()
		bytes := make([]byte, size)
		for at := 0; at < size; {
			result, err := owner.ReadInto(ctx, bytes[at:])
			if err != nil || result.Progress.Filled == 0 {
				t.Fatalf("v4 read: %+v, %v", result, err)
			}
			at += int(result.Progress.Filled)
		}
		return bytes
	}
	var response protocolv4.ProxyHTTPResponse
	if err := protocolv4.DecodeProxyMetadata(read(int(binary.BigEndian.Uint32(read(4)))), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Status != 200 {
		t.Fatalf("response: %+v", response)
	}
	var body []byte
	for {
		length := binary.BigEndian.Uint32(read(4))
		if length == 0 {
			break
		}
		body = append(body, read(int(length))...)
	}
	var terminal protocolv4.ProxyBodyEnd
	if err := protocolv4.DecodeProxyMetadata(read(int(binary.BigEndian.Uint32(read(4)))), &terminal); err != nil {
		t.Fatal(err)
	}
	if string(body) != "v4-proxy" {
		t.Fatalf("body: %q", body)
	}
	if err := owner.Finish(ctx); err != nil {
		t.Fatal(err)
	}
}
