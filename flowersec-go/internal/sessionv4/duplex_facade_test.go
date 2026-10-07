package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func readFacadeEOF(ctx context.Context, stream *StreamOwnership) ([]byte, error) {
	var output []byte
	var scratch [17]byte
	for {
		result, err := stream.ReadInto(ctx, scratch[:])
		output = append(output, scratch[:int(result.Progress.Filled)]...)
		if err != nil {
			return output, err
		}
		if result.ReadTerminal == protocolv4.V4ReadTerminalEof {
			return output, nil
		}
	}
}

func TestOwnedDuplexBridgeTransfersFactoryOwnersAndKeepsReverseHalf(t *testing.T) {
	cores, _, ctx := factoryCorePair(t, "stream", factoryStreamConfig())
	a, b := factoryOpenPair(t, cores, ctx), factoryOpenPair(t, cores, ctx)
	bridge, err := NewOwnedDuplexBridge(ctx, a[0], b[0], DuplexOptions{ChunkBytes: 17, TimeoutMS: 3000, CleanupTimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bridge.Abort() })
	// The obsolete handles can be closed repeatedly without resetting the
	// slots now owned by the bridge. No alias can resume I/O on either slot.
	for _, old := range []*StreamOwnership{a[0], b[0]} {
		if err := old.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := old.Write(context.Background(), []byte("alias")); !errors.Is(err, ErrStreamOwned) {
			t.Fatal("obsolete alias accepted", err)
		}
	}
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Start(); err != nil {
		t.Fatal("repeat start", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if observation, err := bridge.Wait(canceled); !errors.Is(err, context.Canceled) || observation.Result != nil {
		t.Fatal(observation, err)
	}
	request := bytes.Repeat([]byte("bounded-window"), 32)
	wrote := make(chan error, 1)
	go func() {
		_, err := a[1].WriteAll(ctx, request)
		if err == nil {
			err = a[1].CloseWrite(ctx)
		}
		wrote <- err
	}()
	received, err := readFacadeEOF(ctx, b[1])
	if err != nil || !bytes.Equal(received, request) {
		t.Fatal("forward bounded copy", len(received), err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if bridge.Progress().Final {
		t.Fatal("forward EOF finished reverse direction")
	}
	reply := []byte("reply after forward EOF")
	go func() {
		_, err := b[1].WriteAll(ctx, reply)
		if err == nil {
			err = b[1].CloseWrite(ctx)
		}
		wrote <- err
	}()
	received, err = readFacadeEOF(ctx, a[1])
	if err != nil || !bytes.Equal(received, reply) {
		t.Fatal("reverse half", string(received), err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 2)
	for _, peer := range []*StreamOwnership{a[1], b[1]} {
		go func(peer *StreamOwnership) { finished <- peer.Finish(ctx) }(peer)
	}
	result, err := bridge.Wait(ctx)
	if err != nil || result.Result == nil || result.Result.Outcome != protocolv4.V4DuplexOutcomeNormal {
		t.Fatal(result, err)
	}
	for range 2 {
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
	}
	repeated, err := bridge.Wait(ctx)
	if err != nil || repeated.Result != result.Result {
		t.Fatal("unstable result", err)
	}
	if result.Result.AToB.Progress.SourceReadBytes != uint64(len(request)) || result.Result.BToA.Progress.DestinationAcceptedBytes != uint64(len(reply)) {
		t.Fatal(result.Result)
	}
}

func TestOwnedDuplexBridgeBusyRefusalPreservesBothOriginalOwners(t *testing.T) {
	cores, fixtures, ctx := factoryCorePair(t, "stream", factoryStreamConfig())
	a, b := factoryOpenPair(t, cores, ctx), factoryOpenPair(t, cores, ctx)
	prepared, err := b[0].PrepareWrite([]byte("busy"), WriteOptions{TimeoutMS: 2000, HardDeadline: streamTestDeadline(t, cores[0].Engine())})
	if err != nil {
		t.Fatal(err)
	}
	before := fixtures[0].root.Snapshot()
	serialA, serialB := a[0].cursorSerial, b[0].cursorSerial
	bridge, err := NewOwnedDuplexBridge(ctx, a[0], b[0], DuplexOptions{ChunkBytes: 4, TimeoutMS: 3000, CleanupTimeoutMS: 100})
	if bridge != nil || err == nil {
		t.Fatal("prepared write was ignored", err)
	}
	after := fixtures[0].root.Snapshot()
	if a[0].cursorSerial != serialA || b[0].cursorSerial != serialB {
		t.Fatal("failed claim consumed owner identity")
	}
	if after.Charged != before.Charged || after.Reservations != before.Reservations {
		t.Fatal("failed claim leaked budget", before, after)
	}
	prepared.Cancel()
	if _, err := a[1].WriteAll(ctx, []byte("a")); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if result, err := a[0].ReadInto(ctx, data[:]); err != nil || result.Progress.Filled != 1 || data[0] != 'a' {
		t.Fatal("first owner was moved on refusal", result, err)
	}
	if _, err := b[1].WriteAll(ctx, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if result, err := b[0].ReadInto(ctx, data[:]); err != nil || result.Progress.Filled != 1 || data[0] != 'b' {
		t.Fatal("second owner was moved on refusal", result, err)
	}
}

func TestOwnedNativeDuplexBridgeUsesSealedTCPAndHalfClose(t *testing.T) {
	cores, fixtures, ctx := factoryCorePair(t, "stream", factoryStreamConfig(), func(c *resourcev4.Config) { c.Limit[resourcev4.Connections] = 1; c.Limit[resourcev4.NativeHandles] = 1 })
	streams := factoryOpenPair(t, cores, ctx)
	endpoint := NativeTCPOptions{RuntimeBytes: 65536, ProviderBytes: 262144}
	options := NativeTCPDialOptions{TimeoutMS: 3000, CleanupTimeoutMS: 100, RuntimeBytes: 65536, Endpoint: endpoint, HardDeadline: streamTestDeadline(t, cores[0].Engine())}
	dialCharge, err := NativeTCPDialCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	socketCharge, err := NativeTCPCharge(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	// The native factory uses the exact same original root and qualified clock.
	reserveNative := func(charge resourcev4.Vector) resourcev4.Reference {
		fixtures[0].next++
		ref, err := fixtures[0].root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{2}, Backing: [16]byte{fixtures[0].next}, Kind: 1000}, charge, fixtures[0].scope.Tenant, fixtures[0].scope.Session)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	dialRef, socketRef := reserveNative(dialCharge), reserveNative(socketCharge)
	listener := nativeListener(t)
	dial, err := StartNativeTCPDial(ctx, cores[0].Engine().Clock(), listener.Addr().(*net.TCPAddr).AddrPort(), options, dialRef, socketRef)
	if err != nil {
		t.Fatal(err)
	}
	native, err := dial.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close(); _ = native.Close() })
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	alias := *native
	bridge, err := NewOwnedNativeDuplexBridge(ctx, streams[0], native, DuplexOptions{ChunkBytes: 17, TimeoutMS: 3000, CleanupTimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bridge.Abort() })
	if err := alias.Close(); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("native alias bypassed claim", err)
	}
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	request := bytes.Repeat([]byte("native"), 32)
	go func() {
		_, err := streams[1].WriteAll(ctx, request)
		if err == nil {
			err = streams[1].CloseWrite(ctx)
		}
		sent <- err
	}()
	received, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(received, request) {
		t.Fatal("TCP write half", len(received), err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if bridge.Progress().Final {
		t.Fatal("native FIN ended reverse half")
	}
	if _, err := peer.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	received, err = readFacadeEOF(ctx, streams[1])
	if err != nil || string(received) != "reply" {
		t.Fatal(string(received), err)
	}
	go func() { sent <- streams[1].Finish(ctx) }()
	result, err := bridge.Wait(ctx)
	if err != nil || result.Result == nil || result.Result.Outcome != protocolv4.V4DuplexOutcomeNormal {
		t.Fatal(result, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	nativeSend, streamSend := result.Result.AToB.SendResult, result.Result.BToA.SendResult
	if nativeSend.NativeSendFinished == nil || !*nativeSend.NativeSendFinished || nativeSend.SendDrained != nil || streamSend.SendDrained == nil || !*streamSend.SendDrained || streamSend.NativeSendFinished != nil {
		t.Fatal("native finish fabricated authentication", nativeSend, streamSend)
	}
}

func TestOwnedDuplexBridgePreservesOriginalCallbackCancellation(t *testing.T) {
	cores, _, ctx := factoryCorePair(t, "stream", factoryStreamConfig())
	a, b := factoryOpenPair(t, cores, ctx), factoryOpenPair(t, cores, ctx)
	parent, cancel := context.WithCancel(ctx)
	defer cancel()
	// Accepted raw handler owners carry this same original invocation context.
	a[0].mu.Lock()
	a[0].operationContext = parent
	a[0].mu.Unlock()
	bridge, err := NewOwnedDuplexBridge(ctx, a[0], b[0], DuplexOptions{ChunkBytes: 4, TimeoutMS: 3000, CleanupTimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bridge.Abort() })
	abort, err := a[0].handlerSupervision()
	if err != nil || abort == nil {
		t.Fatal("handler supervision lost detached bridge signal", err)
	}
	select {
	case <-abort:
		t.Fatal("ownership transfer canceled original callback")
	default:
	}
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-abort:
	case <-ctx.Done():
		t.Fatal("callback cancellation did not abort bridge")
	}
	result, err := bridge.Wait(ctx)
	if !errors.Is(err, context.Canceled) || result.Result == nil || result.Result.Outcome != protocolv4.V4DuplexOutcomeAborted {
		t.Fatal("original callback lifetime was discarded", result, err)
	}
}
