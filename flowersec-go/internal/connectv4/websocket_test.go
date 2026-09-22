package connectv4

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
	ws "github.com/gorilla/websocket"
)

func TestWebSocketFactoryRefusalJoinsOriginalProvider(t *testing.T) {
	var upgrades atomic.Int32
	peerDone := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := ws.Upgrader{Subprotocols: []string{websocket.SubprotocolLocal}}
		conn, err := u.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		upgrades.Add(1)
		_, _, err = conn.ReadMessage()
		if err == nil {
			t.Error("failed preparation published application/credential bytes")
		}
		peerDone <- struct{}{}
	}))
	defer server.Close()
	limit := resourcev4.Vector{}
	for i := range limit {
		limit[i] = 1 << 26
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 4, ReservationSlots: 8, ReferenceSlots: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 8192, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer environment.Release()
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 10000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1000, UpperMS: 1100}); err != nil {
		t.Fatal(err)
	}
	deadline, err := timev4.NewDeadline(clock, 10000)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/flowersec/v4/local"
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddrPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	owner.Backing = [16]byte{2}
	factory := WebSocketConsumerFactory{PreparationWorkUnits: 128, Root: root, Owner: owner, Environment: environment,
		Options: websocket.Options{MaxMessageBytes: 264, ReadBufferBytes: 125, WriteBufferBytes: 125, HandshakeBytes: 4096, MaxControlsPerSecond: 8,
			HandshakeTimeout: time.Second, MessageTimeout: time.Second, RuntimeBytes: 16384, ProviderRuntimeBytes: 65536, ProviderTasks: 4},
		Dial: websocket.DialConfig{URL: endpoint, RemoteAddress: address, Subprotocol: websocket.SubprotocolLocal, CheckPolicy: func(actual *url.URL, numeric netip.AddrPort, headers http.Header) error {
			if actual.String() != endpoint || numeric != address || !numeric.Addr().IsLoopback() || len(headers) != 0 {
				return resourcev4.ErrConfiguration
			}
			return nil
		}}}
	// The trusted route checker is independently injected. This test exercises
	// provider ownership on either side of that gate, not route qualification.
	request := sessionv4.CarrierPreparationRequest{Budget: sessionv4.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}, Config: sessionv4.PreparedCarrierConfig{Environment: environment, Deadline: deadline}, Route: []byte{1}}
	for _, veto := range []bool{true, false} {
		refusal := errors.New("test route refusal")
		factory.CheckRoute = func(sessionv4.CarrierPreparationRequest, websocket.DialConfig) error {
			if veto {
				return refusal
			}
			return nil
		}
		before := root.Snapshot()
		prepared, err := factory.PrepareCarrier(context.Background(), request)
		if err == nil || prepared != nil {
			t.Fatal("invalid wrapper was prepared", err)
		}
		if veto && (!errors.Is(err, refusal) || upgrades.Load() != 0) {
			t.Fatal("route refusal dialed an endpoint", err)
		}
		if !veto {
			select {
			case <-peerDone:
			case <-time.After(3 * time.Second):
				t.Fatal("failed wrapper orphaned physical WebSocket")
			}
			if upgrades.Load() != 1 {
				t.Fatal("factory did not execute exactly one real upgrade")
			}
		}
		if root.Snapshot() != before {
			t.Fatal("factory returned before actual resource retirement")
		}
	}
}
