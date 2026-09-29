package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestNativeCapacityPlanAdmits1024BusinessWithFullInternalGeometry(t *testing.T) {
	c := corePlanUnitConfig(t, true)
	c.Session = testSessionContract(t, protocolv4.DHProfileX25519, "execution", 65536, 1035, 0, c.Session.SessionNotAfterMS, 1<<20)
	c.applicationServices = true
	c.MaxScopes, c.PendingScopes = 1035, 128
	c.Open = OpenLimits{Active: 1035, Opening: 128, Terminal: 4096, RejectionReserve: 128, IngressItems: 128, IngressBytes: 512 << 10,
		PerClass: [3]uint32{1024, 10, 1}, PerOpener: [2][3]uint32{{1024, 5, 1}, {1024, 5}},
		Protected: [2][3]uint32{{0, 5, 1}, {0, 5}}, Lifetime: [2][3]uint64{{1 << 20, 1 << 20, 16}, {1 << 20, 1 << 20}}}
	c.SendWorkers, c.NativeAuthWorkers, c.WorkSlots = [3]uint32{1024, 10, 1}, 1, 4
	c.Streams = factoryStreamConfig()
	c.Streams.ReceivePoolBytes = 1 << 20
	charge, _, err := SessionCoreRequirements(c)
	if err != nil {
		t.Fatal("full declared native geometry cannot be admitted", err)
	}
	if charge[resourcev4.Tasks] < 1035 {
		t.Fatal("native publication workers escaped accounting")
	}
	broken := c
	broken.SendWorkers[0]--
	if _, _, err := SessionCoreRequirements(broken); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("stalled native direction could consume healthy service", err)
	}
	broken = c
	broken.WorkSlots = broken.NativeAuthWorkers
	if _, _, err := SessionCoreRequirements(broken); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("input partition consumed final outgoing workspace", err)
	}
}

func TestNativeTransport1024BusinessStreamsRetainIndependentOutput(t *testing.T) {
	cores, ctx := nativeTransportCorePair(t, protocolv4.DHProfileX25519, "transport", "capacity")
	streams := make([][2]*StreamOwnership, 0, 1024)
	for range 1024 {
		streams = append(streams, factoryOpenPair(t, cores, ctx))
	}
	for _, core := range cores {
		if usage := core.Admission().Usage(); usage.Active != 1024 {
			t.Fatal("positive Stream count", usage)
		}
		if slots := core.Engine().OrdinaryWorkSlots(); slots != 3 {
			t.Fatal("1024 native owners multiplied crypto workspaces", slots)
		}
	}
	// More stalled original outputs than total crypto positions must not hold
	// the healthy direction's authentication or publication workspace.
	for i := range 8 {
		stream := streams[i][0]
		w := &nativeDelayedWriter{destination: stream.flow.send.writer.writer, entered: make(chan struct{}), returned: make(chan struct{})}
		stream.flow.send.writer.writer = w
		defer close(w.returned)
		go func() { _, _ = stream.WriteAll(ctx, []byte("blocked")) }()
		select {
		case <-w.entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	healthy := streams[len(streams)-1]
	nativeTransfer(t, ctx, healthy[0], healthy[1], "1024 independent send")
	nativeTransfer(t, ctx, healthy[1], healthy[0], "1024 independent receive")
	// Close remains observable before the original blocked provider tails exit.
	cores[0].Close()
	observer, stop := context.WithCancel(context.Background())
	stop()
	if err := cores[0].WaitCleanup(observer); !errors.Is(err, context.Canceled) {
		t.Fatal("cleanup returned original outputs early", err)
	}
}
