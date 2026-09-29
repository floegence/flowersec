package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestChannelCleanupAfterRetirementBeforeOwnerRelease(t *testing.T) {
	for _, kind := range []string{"management", "rpc", "notify", "unbound"} {
		t.Run(kind, func(t *testing.T) {
			f := newServiceFixtureResources(t, 1, [3]uint32{1}, 64, 2, testAuthorization{}, true, []resourcev4.Vector{StreamOwnershipCharge()})
			ingress := newSharedIngressForTest(t, f.local)
			f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
			a := f.local.admission
			h := OpenHandle{a, f.flows[0].receive.scope}
			ref := f.reserve(t, StreamOwnershipCharge())
			defer ref.Release()
			owner := ownFixtureStream(t, f, h, ref)
			// The fixture creates a distinct association for each OPEN. Attach
			// this one to its original shared reader before terminal cleanup.
			a.mu.Lock()
			slot, err := a.slot(h)
			if err == nil {
				slot.carrier.shared = ingress
			}
			a.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := owner.Cancel(); err != nil {
				t.Fatal(err)
			}
			// Exchange the actual authenticated STOP, STOPPED and DRAINED
			// messages while the original Stream owner is still retained.
			for _, terminal := range []struct {
				from, to *openEndpoint
				kind     terminalMessage
			}{
				{f.local, f.peer, terminalStopped},
				{f.local, f.peer, terminalStop},
				{f.peer, f.local, terminalStopped},
				{f.peer, f.local, terminalDrained},
				{f.local, f.peer, terminalDrained},
			} {
				from := terminal.from
				if _, err := from.admission.publishTerminalMessage(ctx, OpenHandle{from.admission, h.scope}, from.maintenance, terminal.kind); err != nil {
					t.Fatal("terminal publication", err)
				}
				applyTerminalWire(t, terminal.to, from.control.Bytes())
				from.control.Reset()
			}
			localRetirement := testRetirement(t, f.local, f.local.maintenance)
			peerRetirement := testRetirement(t, f.peer, f.peer.maintenance)
			if _, err := localRetirement.Start(ctx, 1, streamTestDeadline(t, f.local.engine)); err != nil {
				t.Fatal(err)
			}
			receiveRetirement(t, f.peer, peerRetirement, f.local.control.Bytes())
			f.local.control.Reset()
			if _, err := peerRetirement.Acknowledge(ctx); err != nil {
				t.Fatal(err)
			}
			receiveRetirement(t, f.local, localRetirement, f.peer.control.Bytes())
			f.peer.control.Reset()
			a.mu.Lock()
			slot, err = a.slot(h)
			retained := err == nil && slot.phase == openHeld && slot.owner == owner && !slot.carrierDone && a.isStable(h.scope)
			a.mu.Unlock()
			if !retained || a.Usage().Active != 1 || a.Usage().PositiveProofs != 1 {
				t.Fatal("retirement ACK refunded the retained owner", retained, a.Usage())
			}
			services := &RPCServices{}
			switch kind {
			case "management":
				err = (&managementChannelOpening{services: services, stream: owner, handle: h}).cleanup()
			case "rpc":
				err = (&rpcChannelOpening{services: services, stream: owner, handle: h}).cleanup()
			case "notify":
				err = (&notifyChannelOpening{services: services, stream: owner, handle: h}).cleanup()
			case "unbound":
				if err = owner.Release(); err == nil {
					err = (&rpcChannelOpening{services: services, handle: h}).cleanup()
				}
			}
			if a.Usage().PositiveProofs == 0 {
				// Collection already retired this flow. The fixture must not
				// attempt a new cleanup through its removed scope at teardown.
				f.flows = nil
			}
			if err != nil {
				t.Fatal("completed original channel cleanup failed", err)
			}
			if a.Usage().Active != 0 || a.Usage().PositiveProofs != 0 {
				t.Fatal("completed original association remained charged", a.Usage())
			}
			if err := a.CarrierClosed(h); err != nil {
				t.Fatal("original completed association was not idempotent", err)
			}
			for _, invalid := range []OpenHandle{{f.peer.admission, h.scope}, {a, h.scope + 2}, {a, 0}} {
				if err := a.CarrierClosed(invalid); !errors.Is(err, ErrOpenAssociation) {
					t.Fatal("foreign or unretired association accepted", invalid.Scope(), err)
				}
			}
		})
	}
}
