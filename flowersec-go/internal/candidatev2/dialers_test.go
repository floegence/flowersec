package candidatev2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gorillaws "github.com/gorilla/websocket"
)

func TestWebSocketAdmissionCloseIsIdempotentAfterDialCancellation(t *testing.T) {
	accepted := make(chan *gorillaws.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		conn, err := (&gorillaws.Upgrader{}).Upgrade(response, request, nil)
		if err != nil {
			t.Errorf("upgrade WebSocket: %v", err)
			return
		}
		accepted <- conn
	}))
	t.Cleanup(server.Close)

	client, _, err := gorillaws.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	t.Cleanup(func() { _ = peer.Close() })

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	handle := &webSocketAdmissionHandle{conn: client}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("close canceled WebSocket admission: %v", err)
	}
}
