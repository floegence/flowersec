package flowersec_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
)

func TestByteStreamListenerServesTLSOnReverseEncryptedStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var record controlplane.AuthorizationRecord
	accepted := make(chan flowersec.Session, 1)
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: []string{"https://consumer.example"},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "reverse-stream")
		},
		OnSession: func(callback context.Context, current flowersec.Session, _ string) error {
			accepted <- current
			<-callback.Done()
			return callback.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, roots := acceptorListenerTLS(t)
	server := newWebSocketTestServer(t, acceptor.Handler(), serverTLS)
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "reverse-stream", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         mustEndpointSet(t, websocketURL(server.URL, flowersec.WebSocketDirectPath)),
		RendezvousGroupID: "reverse-stream", ListenerAudience: "test", UpstreamAddress: "127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	record = issued.AuthorizationRecord()
	client := connectIssued(t, server, issued, "https://consumer.example")
	defer client.Close()
	var gateway flowersec.Session
	select {
	case gateway = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer gateway.Close()
	served := make(chan error, 1)
	go func() {
		incoming, err := client.AcceptStream(ctx)
		if err != nil {
			served <- err
			return
		}
		listener, err := flowersec.NewByteStreamListener(ctx, incoming.Stream)
		if err != nil {
			served <- err
			return
		}
		defer listener.Close()
		httpServer := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || r.Host != "localhost" || r.Header.Get("Origin") != "https://consumer.example" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = io.Copy(w, r.Body)
		})}
		defer httpServer.Close()
		served <- httpServer.Serve(tls.NewListener(listener, serverTLS.Clone()))
	}()
	stream, err := gateway.OpenStream(ctx, "application.https", flowersec.StreamMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := flowersec.NewByteStreamConn(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, DialContext: func(context.Context, string, string) (net.Conn, error) { return connection, nil }}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport}
	for range 2 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/", nil)
		req.Header.Set("Origin", "https://consumer.example")
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status %d", res.StatusCode)
		}
	}
	cancel()
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("reverse TLS listener survived cancellation")
	}
}
