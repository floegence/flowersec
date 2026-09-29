package ledgerv4_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func liveService(t *testing.T, h *ledgerv4.LiveServiceTestHarness, rate, burst uint16) *controlv4.LiveSpendService {
	t.Helper()
	c := controlv4.LiveSpendServiceConfig{Store: h.Store, Clock: h.Clock, MaxRecordBytes: 65536, RequestsPerMinute: rate, Burst: burst, WorkMS: 2000, RuntimeBytes: 8192}
	service, read, err := controlv4.LiveSpendServiceCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 4096})
	t.Cleanup(dependencies.Release)
	s, err := controlv4.NewLiveSpendService(c, h.Reserve(service), h.Reserve(read), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestLiveSpendServiceFactsAndOriginalBytesShareBoundedRate(t *testing.T) {
	h := ledgerv4.NewLiveServiceTestHarness(t, true, 2)
	s := liveService(t, h, 60, 3)
	ctx := context.Background()
	baseline := h.Snapshot()
	r, err := s.QuerySpendReceipt(ctx, h.Access, h.Deadline)
	if err != nil || r.State != ledgerv4.SpendConsumed || r.AuthorizationOutcome != ledgerv4.AuthorizationAuthorized {
		t.Fatal(r, err)
	}
	for _, attempt := range []uint8{3, 1} {
		err = s.DeliverOriginalClientMaterial(ctx, h.Access, h.Deadline, attempt, func(_ context.Context, b []byte) error {
			if !bytes.Equal(b, h.Proof()) {
				t.Error("material read changed the original signed bytes")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.QuerySpendReceipt(ctx, h.Access, h.Deadline); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("read operations bypassed the shared rate bound", err)
	}
	if after := h.Snapshot(); after.Charged != baseline.Charged || after.References != baseline.References {
		t.Fatal("a completed read retained a second row owner", baseline, after)
	}
	// Frequent refused calls cannot postpone refill by resetting its anchor.
	for i := uint64(1); i <= 5; i++ {
		h.Tick(i * 100)
		if _, err = s.QuerySpendReceipt(ctx, h.Access, h.Deadline); !errors.Is(err, resourcev4.ErrCapacity) {
			t.Fatal("early refill", err)
		}
	}
	h.Tick(1100)
	if _, err = s.QuerySpendReceipt(ctx, h.Access, h.Deadline); err != nil {
		t.Fatal("continuous rate refill did not make progress", err)
	}
}

func TestLiveSpendServiceNoMaterialFromSpendingOrDenied(t *testing.T) {
	for _, tc := range []struct {
		name     string
		consumed bool
		outcome  uint64
	}{{"spending", false, 0}, {"unknown", true, 0}, {"denied", true, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			h := ledgerv4.NewLiveServiceTestHarness(t, tc.consumed, tc.outcome)
			s := liveService(t, h, 60, 3)
			called := false
			err := s.DeliverOriginalClientMaterial(context.Background(), h.Access, h.Deadline, 2, func(context.Context, []byte) error { called = true; return nil })
			if !errors.Is(err, ledgerv4.ErrMaterialNotReady) || called {
				t.Fatal("non-authorized state produced material", err, called)
			}
			h.Deny(true)
			if r, err := s.QuerySpendReceipt(context.Background(), h.Access, h.Deadline); !errors.Is(err, ledgerv4.ErrDenied) || r != (ledgerv4.SpendReceipt{}) {
				t.Fatal("unauthorized query revealed history", r, err)
			}
		})
	}
}

func TestLiveSpendServiceCloseKeepsActualWriterCharged(t *testing.T) {
	h := ledgerv4.NewLiveServiceTestHarness(t, true, 2)
	s := liveService(t, h, 60, 3)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.DeliverOriginalClientMaterial(context.Background(), h.Access, h.Deadline, 1, func(ctx context.Context, b []byte) error {
			close(entered)
			<-release
			if !bytes.Equal(b, h.Proof()) {
				t.Error("close erased live borrowed writer bytes")
			}
			return ctx.Err()
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer was not reached")
	}
	active := h.Snapshot()
	s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("close reported cleanup while writer remained active", err)
	}
	if after := h.Snapshot(); after.Charged != active.Charged || after.References != active.References {
		t.Fatal("close returned active I/O responsibility", active, after)
	}
	if _, err := s.QuerySpendReceipt(context.Background(), h.Access, h.Deadline); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("closed service admitted another query", err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("cancelled handoff reported success")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}
