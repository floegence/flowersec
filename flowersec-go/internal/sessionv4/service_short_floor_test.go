package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// Hold every remaining byte and root reference. The original reader and fixed
// refusal table must still accept legal input; no fake private budget is used.
func saturateServiceRoot(t *testing.T, f *serviceDispatchFixture) {
	t.Helper()
	s := f.f.root.Snapshot()
	hold := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: s.Limit[resourcev4.SDKBytes] - s.Charged[resourcev4.SDKBytes]})
	var aliases []resourcev4.Reference
	for {
		alias, err := hold.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		aliases = append(aliases, alias)
	}
	t.Cleanup(func() {
		for _, alias := range aliases {
			alias.Release()
		}
		hold.Release()
	})
}

func TestServiceShortFloorRunsAtByteAndReferenceCapacity(t *testing.T) {
	for _, mode := range []uint8{0, 1} {
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			var calls atomic.Uint32
			f := newServiceDispatchFixtureConfigured(t, func(_ context.Context, r UnaryRequest, w *UnaryResponse) (uint32, error) {
				calls.Add(1)
				input, _, err := r.Input.Bytes()
				if err != nil {
					return 0, err
				}
				_, err = w.Write(input)
				return 0, err
			}, true, ApplicationShort)
			saturateServiceRoot(t, f)
			before := f.f.root.Snapshot()
			for range 3 {
				f.request(t, []byte("short request"), mode, 2000)
				if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
					t.Fatal("protected callback could not enter original executor", err)
				}
				header, body := f.response(t)
				if header.IsSDKError() || !bytes.Equal(body, []byte("short request")) {
					t.Fatal(header.Kind(), body)
				}
				waitExecutorIdle(t, f.f.executor)
				f.dispatch.Advance()
				if after := f.f.root.Snapshot(); after != before {
					t.Fatal("protected use changed original root charge", before, after)
				}
			}
			if calls.Load() != 3 {
				t.Fatal(calls.Load())
			}
		})
	}
}

func TestServiceShortFloorCannotBeUsedByResidentInput(t *testing.T) {
	var calls atomic.Uint32
	f := newServiceDispatchFixtureConfigured(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) {
		calls.Add(1)
		return 0, nil
	}, true, ApplicationResident)
	saturateServiceRoot(t, f)
	before := f.f.root.Snapshot()
	f.request(t, []byte("resident"), 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err == nil {
		t.Fatal("resident consumed short input reserve")
	}
	header, _ := f.response(t)
	if !header.IsSDKError() || calls.Load() != 0 {
		t.Fatal("resident callback bypassed full admission")
	}
	if after := f.f.root.Snapshot(); after != before {
		t.Fatal("refusal lost protected charge", before, after)
	}
}

func TestServiceShortFloorRetainsOriginalProviderTail(t *testing.T) {
	f := newServiceDispatchFixtureConfigured(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { return 0, nil }, true, ApplicationShort)
	saturateServiceRoot(t, f)
	before := f.f.root.Snapshot()
	f.request(t, []byte("input"), 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	waitExecutorIdle(t, f.f.executor)
	f.sink.held.Store(true)
	if progressed, err := f.publisher.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	f.dispatch.Advance()
	if f.network.Snapshot().IncomingGeneral != 0 {
		t.Fatal("original network reply did not finish")
	}
	var refs [5]resourcev4.Reference
	if err := resourcev4.CheckoutProtectedBatch(f.dispatch.short[:], refs[:]); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("logical reply completion reused physical output tail", err)
	}
	if after := f.f.root.Snapshot(); after != before {
		t.Fatal("provider tail changed protected root charge", before, after)
	}
	f.sink.held.Store(false)
	if _, err := f.publisher.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.dispatch.Advance()
	if err := resourcev4.CheckoutProtectedBatch(f.dispatch.short[:], refs[:]); err != nil {
		t.Fatal("actual publication did not return floor", err)
	}
	for _, ref := range refs {
		ref.Release()
	}
}
