package transporttest

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestConnectionControllerRetriesTLSInterruptionAfterDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	interrupted := make(chan bool, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		connection, err := listener.AcceptTCP()
		if err != nil {
			interrupted <- false
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
		var record [5]byte
		_, err = io.ReadFull(connection, record[:])
		if err == nil {
			_, err = io.CopyN(io.Discard, connection, int64(binary.BigEndian.Uint16(record[3:])))
		}
		interrupted <- err == nil && record[0] == 22
	}()
	defer func() { _ = listener.Close(); <-joined }()
	fixture := newCurrentControllerHandlerFixture()
	endpoint, err := OpenProductDirectEndpointWithHandlers(ctx, carrier.KindWebSocket, fixture.configure)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := endpoint.Close(); err != nil {
			t.Error(err)
		}
	}()
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewProductControllerTLSInterruptionSource(endpoint, address, fixture.configure)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	controller, err := source.NewController(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeControllerTest(t, controller)
	defer fixture.close(t)
	if err = controller.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := controller.WaitForSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.WaitServer(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err = endpoint.InterruptConnections(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-interrupted:
		if !got {
			t.Fatal("retry did not reach the real TLS ClientHello")
		}
	case <-ctx.Done():
		t.Fatal("controller did not attempt the independently installed TLS destination")
	}
	recovered := waitCurrentControllerReplacement(t, ctx, controller, first)
	recoveredServer, err := source.WaitServer(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	bound := fixture.bind(t, ctx, source.ServerRuntime(2), recoveredServer)
	var response struct {
		Generation int32             `json:"generation"`
		Request    map[string]string `json:"request"`
	}
	if err = json.Unmarshal(currentControllerCall(t, ctx, bound, currentControllerClientRPC, []byte(`{"phase":"recovered"}`)), &response); err != nil || response.Generation != 1 || response.Request["phase"] != "recovered" {
		t.Fatalf("recovered original client handler: %+v %v", response, err)
	}
	if recovered == first {
		t.Fatal("TLS interruption reused the prior Session")
	}
	if source.AcquisitionCount() != 3 || source.SpendCount(0) != 1 || source.SpendCount(1) != 0 || source.RetireCount(1) != 1 || source.SpendCount(2) != 1 {
		t.Fatal("TLS interruption spent a refused lease, omitted retirement, or reacquired a published material")
	}
	if source.records[1].accepted.Claimed() {
		t.Fatal("interrupted TLS exposed the admission credential to accepted lookup")
	}
	if current, err := controller.CaptureSession(); err != nil || current != recovered {
		t.Fatal("retry did not publish the independently admitted current Session")
	}
}
