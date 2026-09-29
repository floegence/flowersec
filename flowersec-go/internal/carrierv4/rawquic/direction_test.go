package rawquic

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestNativeCloseWriteAfterPeerStopReturnsProtectedCapacity(t *testing.T) {
	for _, normal := range []bool{true, false} {
		name := "reset"
		if normal {
			name = "drained"
		}
		t.Run(name, func(t *testing.T) {
			client, server := ownedTestPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			maintenance, err := client.OpenMaintenance(ctx)
			if err != nil {
				t.Fatal(err)
			}
			retireTestStream(t, maintenance)
			if _, err := maintenance.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			peerMaintenance, err := server.AcceptMaintenance(ctx)
			if err != nil {
				t.Fatal(err)
			}
			retireTestStream(t, peerMaintenance)
			var positions [1]native.StreamProtection
			if err := client.ProtectNativeStreams(positions[:]); err != nil {
				t.Fatal(err)
			}
			position := positions[0]
			defer position.Close()
			stream, err := position.Open(ctx)
			if err != nil {
				t.Fatal(err)
			}
			left := stream.(*OwnedStream)
			retired := false
			t.Cleanup(func() {
				if !retired {
					_ = left.Close()
					if err := left.Retire(); err != nil {
						t.Error(err)
					}
				}
			})
			if _, err := left.Write([]byte{7}); err != nil {
				t.Fatal(err)
			}
			right, err := server.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			retireTestStream(t, right)
			var received [1]byte
			if _, err := io.ReadFull(right, received[:]); err != nil || received[0] != 7 {
				t.Fatal(received, err)
			}
			want := native.ErrDirectionReset
			if normal {
				want, err = native.ErrNormalDrained, right.StopSendingDrained()
			} else {
				err = right.StopSending()
			}
			if err != nil {
				t.Fatal(err)
			}
			// Wait for the actual peer STOP before CloseWrite; observing its
			// cause must not call WriteStopReason, which also updates lifecycle.
			select {
			case <-left.WriteContext().Done():
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if cause := streamDirectionFailure(context.Cause(left.WriteContext())); !errors.Is(cause, want) {
				t.Fatal("missing peer stop", cause)
			}
			closeErr := left.CloseWrite()
			if left.Context().Err() != nil {
				t.Fatal("send stop terminated the live reverse direction", closeErr, left.Context().Err())
			}
			if err := left.StopSendingDrained(); err != nil {
				t.Fatal(err)
			}
			if err := left.CloseDirections(); err != nil {
				t.Fatal("ended directions retained the provider slot", closeErr, err)
			}
			if err := position.CheckAvailable(); !errors.Is(err, resourcev4.ErrCapacity) {
				t.Fatal("direction close refunded an unretired stream", err)
			}
			if err := left.Retire(); err != nil {
				t.Fatal(err)
			}
			retired = true
			replacement, err := position.Open(ctx)
			if err != nil {
				t.Fatal("retired direction did not return its protected capacity", err)
			}
			retireTestStream(t, replacement.(*OwnedStream))
		})
	}
}
