package sessionv4

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	carrierws "github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	ws "github.com/gorilla/websocket"
)

var _ InitialMessages = (*carrierws.Messages)(nil)

// This cross-layer test lives with Session, which owns envelope boundaries.
// The provider still uses actual HTTP upgrade and native WebSocket messages.
func TestMessageInputRejectsEnvelopeBoundaries(t *testing.T) {
	valid, err := (protocolv4.Envelope{FrameType: protocolv4.FramePing, Payload: []byte{1}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		frames [][]byte
	}{
		{"empty", [][]byte{{}}}, {"short", [][]byte{{1, 2}}},
		{"split", [][]byte{valid[:8], valid[8:]}},
		{"concatenated", [][]byte{append(append([]byte{}, valid...), valid...)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := admissionIntegration(t, context.Background())
			peers := make(chan *ws.Conn, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				u := ws.Upgrader{Subprotocols: []string{carrierws.SubprotocolLocal}}
				connection, err := u.Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				peers <- connection
			}))
			t.Cleanup(server.Close)
			reserve := func(position uint32, charge resourcev4.Vector, err error) resourcev4.Reference {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				ref, err := f.root.Reserve(admissionResourceKey(f.owner, position), charge)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(ref.Release)
				return ref
			}
			options := carrierws.Options{MaxMessageBytes: 264, ReadBufferBytes: 125, WriteBufferBytes: 125,
				HandshakeBytes: 4096, MaxControlsPerSecond: 8, HandshakeTimeout: time.Second, MessageTimeout: time.Second,
				RuntimeBytes: 16384, ProviderRuntimeBytes: 65536, ProviderTasks: 4}
			charge, err := carrierws.Charge(options)
			ref := reserve(910, charge, err)
			address := netip.MustParseAddrPort(server.Listener.Addr().String())
			provider, err := carrierws.Dial(context.Background(), carrierws.DialConfig{
				URL: "ws" + strings.TrimPrefix(server.URL, "http") + "/flowersec/v4/local", RemoteAddress: address,
				Subprotocol: carrierws.SubprotocolLocal, CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { return nil },
			}, options, ref, f.environment)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = provider.Close()
				if err := provider.WaitCleanup(context.Background()); err != nil {
					t.Error(err)
				}
				if err := provider.Retire(); err != nil {
					t.Error(err)
				}
			})
			peer := <-peers
			t.Cleanup(func() { _ = peer.Close() })
			inputOptions := SessionMessageInputOptions{MaxFrame: 256, WriteSlots: 3, RuntimeBytes: 16384}
			charge, err = SessionMessageInputCharge(inputOptions)
			input, err := NewSessionMessageInput(context.Background(), provider, inputOptions, reserve(911, charge, err), f.environment)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = input.Close()
				if err := input.WaitCleanup(context.Background()); err != nil {
					t.Error(err)
				}
				if err := input.Retire(); err != nil {
					t.Error(err)
				}
			})
			for _, wire := range tc.frames {
				if err := peer.WriteMessage(ws.BinaryMessage, wire); err != nil {
					t.Fatal(err)
				}
			}
			var dst [512]byte
			if n, err := input.Read(dst[:]); n != 0 || !errors.Is(err, ErrSessionMessageFraming) {
				t.Fatalf("exposed invalid envelope: %d %v", n, err)
			}
		})
	}
}
