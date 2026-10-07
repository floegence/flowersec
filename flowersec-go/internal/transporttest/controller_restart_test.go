package transporttest

import (
	"bytes"
	"context"
	"errors"
	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"io"
	"testing"
	"time"
)

func waitCurrentControllerReplacement(t *testing.T, ctx context.Context, controller *fs.ConnectionController, previous *fs.Session) *fs.Session {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, err := controller.CaptureSession()
		if err == nil && current != previous {
			return current
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("original controller did not publish a fresh Session: %v, snapshot=%+v", context.Cause(ctx), controller.Snapshot())
			return nil
		}
	}
}

// The actual UDP listener is closed and joined before a new native listener is
// opened at its signed deployment address. The independently installed
// namespace and consumer store remain original throughout the host restart.
func TestConnectionControllerRealNetworkRestartReconnect(t *testing.T) {
	// This isolated listener owns its address and durable stores. Its real
	// native idle-loss window can overlap unrelated transport workflows.
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 105*time.Second)
	defer cancel()
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	// Every generation is independently signed before Controller.Start. The
	// activation and delegation must outlive native idle-loss observation.
	reporter.ActivationWindowMS = 120000
	endpoint, err := openProductDirectEndpoint(ctx, carrier.KindRawQUIC, "127.0.0.1", "127.0.0.1", releaseRunnerOrigin, protocolv4.DHProfileX25519, defaultMaxInboundStreams, nil, reporter)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := endpoint.Close(); err != nil {
			t.Error(err)
		}
	}()
	source, err := NewProductControllerArtifactSource(endpoint, []ControllerArtifactPlan{ControllerPlanCurrentPin, ControllerPlanCurrentPin})
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
	if err = controller.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := controller.WaitForSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstServer, err := source.WaitServer(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstPair, err := source.NewPair(ctx, first, firstServer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := firstPair.Close(); err != nil {
			t.Error(err)
		}
	}()
	oldStream, err := first.OpenStream(ctx, "native-isolation", fs.EmptyStreamMetadata())
	if err != nil {
		t.Fatal(err)
	}
	defer oldStream.Close()
	oldIncoming, err := firstServer.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer oldIncoming.Stream.Close()
	if _, err = oldStream.WriteAll(ctx, []byte("before-restart")); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len("before-restart"))
	if _, err = io.ReadFull(oldIncoming.Stream, body); err != nil || string(body) != "before-restart" {
		t.Fatalf("original stream before restart: %q %v", body, err)
	}
	resume, err := source.PausePreparations()
	if err != nil {
		t.Fatal(err)
	}
	defer resume()
	originalListener := endpoint.nativeServer()
	restart, stop := context.WithTimeout(ctx, 5*time.Second)
	err = endpoint.RestartListener(restart)
	stop()
	if err != nil {
		t.Fatalf("actual UDP listener restart: %v", err)
	}
	if endpoint.nativeServer() == originalListener || endpoint.nativeServer().Address != originalListener.Address {
		t.Fatal("restart failed to create a new native listener at the complete signed address")
	}
	resume()
	// QUIC starts its unchanged 60-second idle window after the first
	// ack-eliciting send, including the default 20-second keepalive PING.
	// Observe both windows without substituting an application close.
	observed, stop := context.WithTimeout(ctx, 85*time.Second)
	if terminal := first.WaitTermination(observed); terminal == nil || observed.Err() != nil {
		stop()
		t.Fatalf("physical listener shutdown did not terminate the old Session: %v", terminal)
	}
	if n, err := oldStream.WriteAll(ctx, []byte("must-not-migrate")); err == nil || n != 0 {
		t.Fatalf("old stream retained submission after interruption: %d %v", n, err)
	}
	if err = errors.Join(oldStream.Close(), oldIncoming.Stream.Close()); err != nil {
		t.Fatal(err)
	}
	if err = first.WaitCleanup(observed); err != nil {
		stop()
		t.Fatalf("old Session retained its actual native cleanup: %v", err)
	}
	stop()
	second := waitCurrentControllerReplacement(t, ctx, controller, first)
	secondServer, err := source.WaitServer(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	secondPair, err := source.NewPair(ctx, second, secondServer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := secondPair.Close(); err != nil {
			t.Error(err)
		}
	}()
	payload := []byte("after-real-listener-restart")
	response, err := secondPair.CallEcho(ctx, payload)
	if err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("fresh original admission after restart: %q %v", response, err)
	}
	if source.AcquisitionCount() != 2 || source.SpendCount(0) != 1 || source.SpendCount(1) != 1 {
		t.Fatal("listener restart changed the original fresh acquisition and independent durable spend facts")
	}
	t.Log("physical UDP interruption produced a fresh Session, a successful RPC, and exactly one durable spend per generation")
	if stream, err := first.OpenStream(ctx, "native-isolation", fs.EmptyStreamMetadata()); err == nil || stream != nil {
		t.Fatal("old Session accepted an OPEN after its listener stopped")
	}
	if n, err := oldStream.WriteAll(ctx, []byte("must-not-migrate")); err == nil || n != 0 {
		t.Fatalf("old stream migrated submission into replacement: %d %v", n, err)
	}
	if result, err := firstPair.CallEcho(ctx, []byte("must-not-replay")); err == nil || len(result) != 0 {
		t.Fatal("old bound RPC replayed into the replacement Session")
	}
	if first == second || firstServer == secondServer {
		t.Fatal("listener restart reused an old original Session handle")
	}
	if err = firstPair.Close(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
