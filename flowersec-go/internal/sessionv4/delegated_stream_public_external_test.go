package sessionv4_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

func TestPublicDelegatedRawServiceRetainsCanceledServeUntilActualReturn(t *testing.T) {
	entered := make(chan *fs.StreamConn, 1)
	canceled, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	var setups, serves atomic.Uint32
	registration := fs.RawStreamHandlerConfig{Kind: "example/delegated", Slots: 1, WorkClass: fs.WorkShort,
		AuthorizeOpen: func(_ context.Context, binding any, metadata []byte) error {
			if binding != 1 || len(metadata) != 0 {
				return errors.New("unexpected delegated application binding")
			}
			return nil
		},
		Delegated: &fs.DelegatedStreamService{
			Options: fs.DelegatedStreamOptions{
				Connection:   fs.StreamConnOptions{FinishTimeoutMS: 30000, CleanupTimeoutMS: 100, RuntimeBytes: 32768},
				RuntimeBytes: 32768, ExternalRuntime: fs.ResourceVector{fs.ProviderBytes: 65536, fs.Tasks: 1, fs.WorkSlots: 1},
			},
			Setup: func(context.Context, any, []byte) (fs.DelegatedStreamServe, error) {
				setups.Add(1)
				return func(ctx context.Context, conn net.Conn) error {
					serves.Add(1)
					original, ok := conn.(*fs.StreamConn)
					if !ok {
						return errors.New("delegated Serve did not receive the original connection")
					}
					entered <- original
					var payload [4]byte
					if _, err := io.ReadFull(conn, payload[:]); err != nil {
						return err
					}
					if _, err := conn.Write(payload[:]); err != nil {
						return err
					}
					<-ctx.Done()
					close(canceled)
					<-release
					return ctx.Err()
				}, nil
			},
		}}
	// The shared fixture provisions independently signed material and real TLS.
	// Registration, Serve, I/O, cancellation and cleanup use public types only.
	publicWebSocketEnvironmentRoundTrip(t, "preauthorized_pool", "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", true, webSocketRoundTripOptions{
		streamRegistration: &registration,
		streamWorkflow: func(ctx context.Context, sessions [2]*fs.Session) {
			stream, err := sessions[0].OpenStream(ctx, registration.Kind, fs.EmptyStreamMetadata())
			if err != nil {
				t.Fatal("public delegated OPEN", err)
			}
			defer stream.Close()
			var original *fs.StreamConn
			select {
			case original = <-entered:
			case <-ctx.Done():
				t.Fatal("public delegated Serve did not start", ctx.Err())
			}
			payload := []byte{0, 1, 128, 255}
			if n, err := stream.WriteAll(ctx, payload); err != nil || n != len(payload) {
				t.Fatal("public delegated write", n, err)
			}
			var reply [4]byte
			if _, err := io.ReadFull(stream, reply[:]); err != nil || !bytes.Equal(reply[:], payload) {
				t.Fatal("delegated Serve changed raw protocol bytes", reply, err)
			}
			if _, err := sessions[0].ProbeLiveness(ctx, 1000); err != nil {
				t.Fatal("delegated Serve blocked Session maintenance", err)
			}
			if err := sessions[1].Close(); err != nil {
				t.Fatal("cancel accepted Session", err)
			}
			select {
			case <-canceled:
			case <-ctx.Done():
				t.Fatal("delegated Serve did not receive cancellation", ctx.Err())
			}
			if status := original.CleanupStatus(); status.Status == "complete" || status.PendingCallbacks != 1 {
				t.Fatal("delegated connection released its actual Serve tail", status)
			}
			if sessions[1].CleanupStatus().Complete {
				t.Fatal("Session cleanup completed before delegated Serve returned")
			}
			finish()
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for original.CleanupStatus().Status != "complete" || !sessions[1].CleanupStatus().Complete {
				select {
				case <-ticker.C:
				case <-ctx.Done():
					t.Fatal("public delegated cleanup retained original owners", original.CleanupStatus(), sessions[1].CleanupStatus())
				}
			}
			if status := original.CleanupStatus(); status.CoreCleanup != "complete" || status.PendingCallbacks != 0 {
				t.Fatal("delegated flow cleanup did not finish", status)
			}
			if setups.Load() != 1 || serves.Load() != 1 {
				t.Fatal("delegated callback was duplicated", setups.Load(), serves.Load())
			}
		},
	})
}
