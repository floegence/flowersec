package sessionv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type maintenanceIngressFixture struct {
	local, peer *openEndpoint
	input       *MaintenanceIngress
	root        *resourcev4.Root
	carrier     *CarrierAssociation
	now         *atomic.Uint64
}

func newMaintenanceIngressFixture(t *testing.T, burst uint32) *maintenanceIngressFixture {
	t.Helper()
	f := &maintenanceIngressFixture{now: new(atomic.Uint64), carrier: &CarrierAssociation{}}
	clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: f.now.Load(), Incarnation: [16]byte{1}}, nil
	})
	f.local, f.peer = newOpenEndpointClock(t, protocolv4.ClientToServer, 2, 2, 1, clock), newOpenEndpointClock(t, protocolv4.ServerToClient, 2, 2, 1, clock)
	assembly, _ := MaintenanceIngressCharge(f.local.engine.MaxFrame())
	decode := protocolv4.DecodeContext{}
	receiver, _ := RecordReceiverCharge(f.local.engine.MaxFrame(), 128, decode)
	limit, _ := assembly.Add(receiver)
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 2, ReferenceSlots: 4, Limit: limit}
	metadata, _ := resourcev4.BackingBytes(config)
	config.Limit[resourcev4.SDKBytes] += metadata
	var err error
	f.root, err = resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	resources := &nativeAssemblyFixture{root: f.root}
	f.input, err = NewMaintenanceIngress(f.local.admission, f.carrier, MaintenanceIngressPolicy{FrameTimeoutMS: 50, RefillMS: 100, Burst: burst}, 128, decode, resources.reserve(t, assembly), resources.reserve(t, receiver))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.local.admission.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := f.input.WaitCleanup(ctx); err != nil {
			t.Error("original maintenance owner did not exit", err)
			return
		}
		if err := f.input.retire(); err != nil || f.root.Snapshot().Reservations != 0 {
			t.Error("maintenance reservation not retired", err, f.root.Snapshot().Reservations)
		}
		f.root.Close()
	})
	return f
}

func (f *maintenanceIngressFixture) ping(t *testing.T, nonce byte) []byte {
	t.Helper()
	f.peer.control.Reset()
	if _, err := f.peer.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, nonce)); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(f.peer.control.Bytes())
}

type maintenanceReadCounter struct{ reads int }

func (r *maintenanceReadCounter) Read([]byte) (int, error) { r.reads++; return 0, io.ErrClosedPipe }

func TestMaintenanceIngressCandidateRetainsOriginalAdmissionOnCapacity(t *testing.T) {
	f := newMaintenanceIngressFixture(t, 4)
	ctx := context.Background()
	held, err := f.local.receiver.Receive(ctx, f.ping(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	next := f.ping(t, 2)
	if _, err := f.input.Read(ctx, f.carrier, bytes.NewReader(next)); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("no definite capacity refusal", err)
	}
	f.input.mu.Lock()
	ready, tokens, length := f.input.ready, f.input.tokens, f.input.length
	f.input.mu.Unlock()
	if !ready || tokens != 3 || length != len(next) {
		t.Fatal("original candidate replaced", ready, tokens, length)
	}
	held.Release()
	noRead := new(maintenanceReadCounter)
	record, err := f.input.Read(ctx, f.carrier, noRead)
	if err != nil || noRead.reads != 0 {
		t.Fatal("capacity retry re-read native input", err, noRead.reads)
	}
	defer record.Release()
	frame, err := record.Body()
	if err != nil || frame.Schema != "PING" || frame.Header.Sequence != 1 {
		t.Fatal(frame, err)
	}
	if err := record.AcceptMessage(); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceIngressHeldPlaintextPreventsAnotherNativeRead(t *testing.T) {
	f := newMaintenanceIngressFixture(t, 2)
	ctx := context.Background()
	record, err := f.input.Read(ctx, f.carrier, bytes.NewReader(f.ping(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	noRead := new(maintenanceReadCounter)
	if _, err := f.input.Read(ctx, f.carrier, noRead); !errors.Is(err, cryptov4.ErrCapacity) || noRead.reads != 0 {
		t.Fatal("held decoder acquired a second native candidate", err, noRead.reads)
	}
	f.input.Close()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.input.WaitCleanup(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("held plaintext disappeared at Close", err)
	}
	if err := f.input.retire(); !errors.Is(err, cryptov4.ErrCapacity) || f.root.Snapshot().Reservations != 2 {
		t.Fatal("early receiver/assembly refund", err)
	}
	record.Release()
}

func TestMaintenanceIngressPartialReadUsesNoAuthenticationSlot(t *testing.T) {
	f := newMaintenanceIngressFixture(t, 2)
	reader := &nativeHeldReader{source: bytes.NewReader(f.ping(t, 1)), before: 9, entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(reader.release) }) }
	defer unblock()
	type result struct {
		record *ReceivedRecord
		err    error
	}
	done := make(chan result, 1)
	go func() { r, err := f.input.Read(context.Background(), f.carrier, reader); done <- result{r, err} }()
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no partial native read")
	}
	f.input.receiver.mu.Lock()
	active := f.input.receiver.active
	f.input.receiver.mu.Unlock()
	if active {
		t.Fatal("partial maintenance input held the full authentication position")
	}
	// The opposite maintenance direction retains its independent key/work slot.
	var out bytes.Buffer
	writer, _ := NewRecordWriter(f.local.engine, 0, &out)
	if _, err := writer.Write(context.Background(), protocolv4.FramePing, pingBody(t, 9)); err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		defer result.record.Release()
		if err := result.record.AcceptMessage(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("complete maintenance frame was not authenticated")
	}
}

func TestMaintenanceIngressPartialDeadlinePreservesActualNativeTail(t *testing.T) {
	for _, before := range []int{0, 1, 9} {
		t.Run(map[int]string{0: "idle input", 1: "partial prefix", 9: "partial body"}[before], func(t *testing.T) {
			f := newMaintenanceIngressFixture(t, 2)
			reader := &nativeHeldReader{source: bytes.NewReader(f.ping(t, 1)), before: before, entered: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			unblock := func() { once.Do(func() { close(reader.release) }) }
			defer unblock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			watch, read := make(chan error, 1), make(chan error, 1)
			go func() { watch <- f.input.Watch(ctx) }()
			go func() {
				r, err := f.input.Read(ctx, f.carrier, reader)
				if r != nil {
					r.Release()
				}
				read <- err
			}()
			select {
			case <-reader.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("no original provider read")
			}
			charge := f.root.Snapshot().Charged
			f.now.Store(51)
			f.input.notify()
			if before == 0 {
				f.input.mu.Lock()
				window := f.input.window
				f.input.mu.Unlock()
				if window != nil {
					t.Fatal("empty idle reader acquired a partial-frame deadline")
				}
				cancel()
			}
			err := nativeResult(t, watch)
			if before != 0 && !errors.Is(err, timev4.ErrExpired) {
				t.Fatal("partial frame outlived original deadline", err)
			}
			if before == 0 && !errors.Is(err, context.Canceled) {
				t.Fatal("idle first-byte wait used partial deadline", err)
			}
			if f.root.Snapshot().Charged != charge {
				t.Fatal("deadline refunded a blocked native alias")
			}
			if err := f.input.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
				t.Fatal(err)
			}
			unblock()
			if err := nativeResult(t, read); err == nil {
				t.Fatal("late native read published after lifetime ended")
			}
		})
	}
}

func TestMaintenanceIngressIdentityRateAndFramingBoundaries(t *testing.T) {
	t.Run("original association", func(t *testing.T) {
		f := newMaintenanceIngressFixture(t, 2)
		reader := new(maintenanceReadCounter)
		if _, err := f.input.Read(context.Background(), &CarrierAssociation{}, reader); !errors.Is(err, ErrOpenAssociation) || reader.reads != 0 {
			t.Fatal(err, reader.reads)
		}
		if err := f.local.engine.CheckApplicationAuthorization(); err != nil {
			t.Fatal("caller identity mistake closed original Session", err)
		}
	})
	for _, mode := range []string{"rate", "foreign scope", "length", "truncated", "no progress"} {
		t.Run(mode, func(t *testing.T) {
			f := newMaintenanceIngressFixture(t, 1)
			ctx := context.Background()
			wire := f.ping(t, 1)
			var reader io.Reader
			var expected error
			switch mode {
			case "rate":
				r, err := f.input.Read(ctx, f.carrier, bytes.NewReader(wire))
				if err != nil {
					t.Fatal(err)
				}
				r.Release()
				wire = f.ping(t, 2)
				expected = ErrMaintenanceRate
			case "foreign scope":
				binary.BigEndian.PutUint64(wire[12:20], 1)
				expected = protocolv4.ErrRecordScope
			case "length":
				binary.BigEndian.PutUint32(wire[:4], f.local.engine.MaxFrame()+1)
				wire = wire[:8]
				expected = protocolv4.ErrPayloadTooLarge
			case "truncated":
				wire = wire[:len(wire)-1]
				expected = io.ErrUnexpectedEOF
			case "no progress":
				reader = nativeNoProgressReader{}
				expected = io.ErrNoProgress
			}
			if reader == nil {
				reader = bytes.NewReader(wire)
			}
			if _, err := f.input.Read(ctx, f.carrier, reader); !errors.Is(err, expected) {
				t.Fatal(err, expected)
			}
			select {
			case <-f.local.engine.Done():
			default:
				t.Fatal("unsafe maintenance input left Session live")
			}
		})
	}
}
