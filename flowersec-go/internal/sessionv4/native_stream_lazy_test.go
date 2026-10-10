package sessionv4

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestNativeTransportLazyReadersKeepAllConcurrentOPENPositions(t *testing.T) {
	var receivers [2][]*RecordReceiver
	cores, ctx := nativeTransportCorePairBeforeRun(t, protocolv4.DHProfileX25519, nil, nil, nil, func(cores [2]*SessionCore, _ context.Context) {
		for role, core := range cores {
			n := core.plan.nativeStreams
			if len(n.readers) != int(core.plan.config.Open.IngressItems) {
				t.Fatal("native transport reduced its preadmitted parallel input positions")
			}
			for _, slot := range n.readers {
				r := slot.receiver
				if r == nil || r.decoder != nil || r.storage != nil || r.reservation.Check() != nil {
					t.Fatal("unread native position allocated arrays or lost original ownership")
				}
				receivers[role] = append(receivers[role], r)
			}
		}
	})
	count := len(receivers[1])
	if count != 2 {
		t.Fatal("parallel fixture no longer supplies its two original OPEN positions", count)
	}
	outgoing := make(chan factoryStreamResult, count)
	var owners []*StreamOwnership
	received := 0
	t.Cleanup(func() {
		for _, core := range cores {
			core.Close()
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for received < count {
			select {
			case result := <-outgoing:
				received++
				if result.stream != nil {
					owners = append(owners, result.stream)
				}
			case <-cleanup.Done():
				t.Error("original concurrent OPEN caller did not exit")
				return
			}
		}
		for _, owner := range owners {
			_ = owner.Cancel()
			if err := owner.Release(); err != nil {
				t.Error(err)
			}
		}
	})
	for range count {
		go func() {
			stream, err := cores[0].OpenStream(ctx, "example/raw", nil, streamTestDeadline(t, cores[0].Engine()))
			outgoing <- factoryStreamResult{stream, err}
		}()
	}
	var pending []OpenHandle
	for range count {
		h, err := cores[1].Admission().NextPending(ctx)
		if err != nil {
			t.Fatal("one pending OPEN consumed another native position", err)
		}
		pending = append(pending, h)
	}
	n := cores[1].plan.nativeStreams
	n.mu.Lock()
	allUsed := true
	for _, slot := range n.readers {
		allUsed = allUsed && slot.used
	}
	n.mu.Unlock()
	if !allUsed {
		t.Fatal("concurrent OPEN did not retain every original reader position")
	}
	for _, r := range receivers[1] {
		r.mu.Lock()
		allocated := r.decoder != nil && len(r.storage) == r.storageUsed && len(r.storage) <= protocolv4.EnvelopePrefixSize+int(r.maxFrame)
		r.mu.Unlock()
		if !allocated {
			t.Fatal("an admitted concurrent OPEN lost its original decoder or exact active backing")
		}
	}
	peers := make(map[uint64]*StreamOwnership, count)
	for _, h := range pending {
		peer, err := cores[1].AcceptStream(ctx, h)
		if err != nil {
			t.Fatal("lazy native reader reduced concurrent admission", err)
		}
		owners = append(owners, peer)
		peers[h.scope] = peer
	}
	for received < count {
		select {
		case result := <-outgoing:
			received++
			if result.err != nil {
				t.Fatal(result.err)
			}
			owners = append(owners, result.stream)
			peer := peers[result.stream.handle.scope]
			if peer == nil {
				t.Fatal("native OPEN replaced its original logical scope")
			}
			nativeTransfer(t, ctx, result.stream, peer, "concurrent native owner")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for _, core := range cores {
		core.Close()
	}
	for _, core := range cores {
		if err := core.plan.nativeStreams.WaitCleanup(ctx); err != nil {
			t.Fatal("original native close worker did not clean up", err)
		}
	}
	for _, group := range receivers {
		for _, r := range group {
			if err := r.WaitCleanup(ctx); err != nil {
				t.Fatal("original native read tail did not clean up", err)
			}
			r.mu.Lock()
			cleared := r.decoder == nil && r.storage == nil
			r.mu.Unlock()
			if !cleared {
				t.Fatal("native cleanup retained lazy receiver arrays")
			}
		}
	}
}
