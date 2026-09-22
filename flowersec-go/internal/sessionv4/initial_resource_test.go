package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func TestInitialResourceReservationIsUniqueAndWaitsForProviderExit(t *testing.T) {
	config := initialTestConfig(t, 0, protocolv4.DHProfileX25519)
	charge, err := InitialCharge(config.Limits)
	if err != nil {
		t.Fatal(err)
	}
	root, ref := testResourceReservation(t, charge, 1)
	config.Reservation = resourcev4.Reference{}
	if _, err := NewInitialStream(context.Background(), config, &initialMemoryStream{}); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("unreserved handshake allocated", err)
	}
	config.Reservation = ref
	stream := &initialBlockedStream{entered: make(chan struct{}), release: make(chan struct{})}
	x, err := NewInitialStream(context.Background(), config, stream)
	if err != nil {
		t.Fatal(err)
	}
	cleanupInitial(t, x)
	ref.Release()
	if _, err := ref.Take(resourcev4.Vector{}); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("handshake quota attached more than once", err)
	}
	wire := initialFixture(t, "client_hello_fields")
	finished := make(chan InitialWriteResult, 1)
	go func() { result, _ := x.Send(protocolv4.FrameNegotiate, initialCopy(wire)); finished <- result }()
	<-stream.entered
	before := root.Snapshot().Charged
	x.Close(context.Canceled)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := x.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) || root.Snapshot().Charged != before {
		t.Fatal("close refunded live handshake/provider storage", err)
	}
	cancel()
	close(stream.release)
	result := <-finished
	if !result.Submitted || result.Complete {
		t.Fatal("cleanup lost original publication facts", result)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := x.WaitCleanup(ctx); err != nil || root.Snapshot().Reservations != 0 {
		t.Fatal("actual initial cleanup failed to return quota", err)
	}
}
