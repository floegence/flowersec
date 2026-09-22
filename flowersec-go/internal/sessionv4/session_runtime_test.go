package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type runtimeTestInput struct {
	io.Reader
	interrupts atomic.Int32
	interrupt  func()
}

func (i *runtimeTestInput) InterruptRead() {
	i.interrupts.Add(1)
	if i.interrupt != nil {
		i.interrupt()
	}
}

type runtimeFixture struct {
	local     *openEndpoint
	resources *nativeAssemblyFixture
	config    SessionRuntimeConfig
}

func newRuntimeFixture(t *testing.T, endpoint *openEndpoint, input RuntimeInput, native bool) *runtimeFixture {
	t.Helper()
	resources := backgroundResources(t, endpoint)
	root := resources.root
	var err error
	f := &runtimeFixture{local: endpoint, resources: resources, config: SessionRuntimeConfig{Admission: endpoint.admission, Input: input, DispatchTimeoutMS: 10000}}
	decode := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
	if native {
		charge, _ := MaintenanceIngressCharge(endpoint.engine.MaxFrame())
		receiver, _ := RecordReceiverCharge(endpoint.engine.MaxFrame(), 128, decode)
		f.config.MaintenanceIngress, err = NewMaintenanceIngress(endpoint.admission, &CarrierAssociation{}, MaintenanceIngressPolicy{FrameTimeoutMS: 50, RefillMS: 10, Burst: 16}, 128, decode, f.resources.reserve(t, charge), f.resources.reserve(t, receiver))
	} else {
		charge, _ := SharedIngressCharge(endpoint.engine.MaxFrame(), 128, decode)
		f.config.SharedIngress, err = NewSharedIngress(endpoint.admission, &CarrierAssociation{}, SharedDiscardPolicy{MaxRecords: 16, MaxBytes: 65536, DurationMS: 100}, 128, decode, f.resources.reserve(t, charge))
	}
	if err != nil {
		t.Fatal(err)
	}
	f.config.Reservation = f.resources.reserve(t, SessionRuntimeCharge())
	t.Cleanup(func() {
		endpoint.admission.Close()
		if g := f.config.SharedIngress; g != nil {
			if err := g.Retire(); err != nil {
				t.Error(err)
			}
		}
		if g := f.config.MaintenanceIngress; g != nil {
			if err := g.retire(); err != nil {
				t.Error(err)
			}
		}
		root.Close()
	})
	return f
}

func (f *runtimeFixture) startOwner(t *testing.T) *SessionRuntime {
	t.Helper()
	r, err := NewSessionRuntime(f.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := r.Retire(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func waitRuntime(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("runtime wait did not end")
		return nil
	}
}

func TestSessionRuntimeRejectsMixedForeignAndDuplicateOwners(t *testing.T) {
	local := newOpenEndpoint(t, 0, 2, 2, 1)
	foreign := newOpenEndpoint(t, 1, 2, 2, 1)
	input := &runtimeTestInput{Reader: bytes.NewReader(nil)}
	f := newRuntimeFixture(t, local, input, false)
	foreignIngress := newSharedIngressForTest(t, foreign)
	for _, change := range []func(*SessionRuntimeConfig){
		func(c *SessionRuntimeConfig) { c.SharedIngress = nil },
		func(c *SessionRuntimeConfig) { c.MaintenanceIngress = &MaintenanceIngress{admission: local.admission} },
		func(c *SessionRuntimeConfig) { c.SharedIngress = foreignIngress },
	} {
		c := f.config
		change(&c)
		if _, err := NewSessionRuntime(c); !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal("invalid composition accepted", err)
		}
	}
	_, other := testResourceReservation(t, SessionRuntimeCharge(), 1)
	c := f.config
	c.Reservation = other
	if _, err := NewSessionRuntime(c); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("private budget root accepted", err)
	}
	f.startOwner(t)
	if _, err := NewSessionRuntime(f.config); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("second runtime accepted", err)
	}
	if _, err := NewIdleWatchdog(local.admission); err == nil {
		t.Fatal("late service added after immutable capture")
	}
}

func TestSessionRuntimeStopsOnFirstIngressFailure(t *testing.T) {
	endpoint := newOpenEndpoint(t, 0, 2, 2, 1)
	input := &runtimeTestInput{Reader: bytes.NewReader(nil)}
	f := newRuntimeFixture(t, endpoint, input, false)
	r := f.startOwner(t)
	if err := r.Run(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatal("lost original reader failure", err)
	}
	if !errors.Is(r.Err(), io.EOF) {
		t.Fatal(r.Err())
	}
	if input.interrupts.Load() != 1 {
		t.Fatal("provider cancellation was not once-only")
	}
}

func TestSessionRuntimeCancellationRetainsActualReaderTail(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared", true: "native"}[native], func(t *testing.T) {
			endpoint := newOpenEndpoint(t, 0, 2, 2, 1)
			held := &resourceHeldReader{source: bytes.NewReader(nil), entered: make(chan struct{}), release: make(chan struct{})}
			input := &runtimeTestInput{Reader: held}
			f := newRuntimeFixture(t, endpoint, input, native)
			r := f.startOwner(t)
			var once sync.Once
			release := func() { once.Do(func() { close(held.release) }) }
			defer release()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- r.Run(ctx) }()
			select {
			case <-held.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("reader not started")
			}
			before := f.resources.root.Snapshot().Charged
			cancel()
			if err := waitRuntime(t, done); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if input.interrupts.Load() != 1 {
				t.Fatal("original provider not interrupted")
			}
			canceled, stop := context.WithCancel(context.Background())
			stop()
			if err := r.WaitCleanup(canceled); !errors.Is(err, context.Canceled) {
				t.Fatal("live reader claimed clean", err)
			}
			if err := r.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
				t.Fatal("live reader retired", err)
			}
			if f.resources.root.Snapshot().Charged != before {
				t.Fatal("provider tail refunded early")
			}
			release()
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := r.WaitCleanup(cleanup); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(r.Err(), context.Canceled) {
				t.Fatal("late EOF overwrote cancellation", r.Err())
			}
		})
	}
}

func TestSessionRuntimeCloseBeforeRunCleansAndIsFinal(t *testing.T) {
	f := newRuntimeFixture(t, newOpenEndpoint(t, 0, 2, 2, 1), &runtimeTestInput{Reader: bytes.NewReader(nil)}, false)
	r := f.startOwner(t)
	r.Close()
	r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(ctx); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("closed owner restarted", err)
	}
	if err := r.Retire(); err != nil {
		t.Fatal(err)
	}
	if r.admission != nil || r.input != nil {
		t.Fatal("retired runtime retained graph")
	}
}

func TestSessionRuntimeIdleClosesBlockedProvider(t *testing.T) {
	local, _, now := idleEndpoints(t, 100)
	reader, writer := io.Pipe()
	defer writer.Close()
	input := &runtimeTestInput{Reader: reader, interrupt: func() { _ = reader.Close() }}
	f := newRuntimeFixture(t, local, input, false)
	r := f.startOwner(t)
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	now.Store(100)
	if err := waitRuntime(t, done); !errors.Is(err, cryptov4.ErrIdle) {
		t.Fatal("lost watchdog cause", err)
	}
	if !errors.Is(r.Err(), cryptov4.ErrIdle) {
		t.Fatal(r.Err())
	}
}

func TestSessionRuntimePublishesOriginalPongOnBothCarriers(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared", true: "native"}[native], func(t *testing.T) {
			local := newOpenEndpoint(t, 0, 2, 2, 1)
			peer := newOpenEndpoint(t, 1, 2, 2, 1)
			output := &serviceTestWriter{frames: make(chan []byte, 4)}
			var err error
			local.maintenance, err = NewRecordWriter(local.engine, 0, output)
			if err != nil {
				t.Fatal(err)
			}
			_, queue := maintenanceMessages(t, local, 2, 4)
			reader, writer := io.Pipe()
			defer writer.Close()
			input := &runtimeTestInput{Reader: reader, interrupt: func() { _ = reader.Close() }}
			f := newRuntimeFixture(t, local, input, native)
			r := f.startOwner(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- r.Run(ctx) }()
			if _, err := peer.maintenance.Write(ctx, protocolv4.FramePing, pingBody(t, 19)); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(peer.control.Bytes()); err != nil {
				t.Fatal(err)
			}
			wire := nextServiceFrame(t, output)
			record, err := peer.receiver.Receive(ctx, wire)
			if err != nil {
				t.Fatal(err)
			}
			body, err := record.Body()
			if err != nil {
				t.Fatal(err)
			}
			nonce, _ := body.Field("nonce").ByteString()
			if body.Schema != "PONG" || len(nonce) != 16 || nonce[0] != 19 {
				t.Fatal("PING was dropped instead of answered")
			}
			record.Release()
			cancel()
			if err := waitRuntime(t, done); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := queue.WaitCleanup(cleanup); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionRuntimePongDeadlineRetainsProviderTail(t *testing.T) {
	local, peer, now := idleEndpoints(t, 0)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	output := idleWriterFunc(func(data []byte) (int, error) { close(entered); <-release; return len(data), nil })
	var err error
	local.maintenance, err = NewRecordWriter(local.engine, 0, output)
	if err != nil {
		t.Fatal(err)
	}
	_, queue := maintenanceMessages(t, local, 2, 4)
	reader, writer := io.Pipe()
	defer writer.Close()
	f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: reader, interrupt: func() { _ = reader.Close() }}, false)
	r := f.startOwner(t)
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	if _, err := peer.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 23)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(peer.control.Bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("PONG publication not started")
	}
	now.Store(501)
	queue.notify()
	if err := waitRuntime(t, done); err == nil || errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("original reply deadline lost", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.WaitCleanup(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("blocked PONG reported cleanup complete", err)
	}
	once.Do(func() { close(release) })
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := r.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRuntimeNativeMaintenanceWaitsForItsOwnCapacity(t *testing.T) {
	local := newOpenEndpoint(t, 0, 2, 2, 1)
	peer := newOpenEndpoint(t, 1, 2, 2, 1)
	output := &serviceTestWriter{frames: make(chan []byte, 4)}
	local.maintenance, _ = NewRecordWriter(local.engine, 0, output)
	maintenanceMessages(t, local, 2, 4)
	if _, err := peer.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 1)); err != nil {
		t.Fatal(err)
	}
	held, err := local.receiver.Receive(context.Background(), peer.control.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	peer.control.Reset()
	if _, err := peer.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 2)); err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer writer.Close()
	f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: reader, interrupt: func() { _ = reader.Close() }}, true)
	r := f.startOwner(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	if _, err := writer.Write(peer.control.Bytes()); err != nil {
		t.Fatal(err)
	}
	held.Release()
	wire := nextServiceFrame(t, output)
	record, err := peer.receiver.Receive(ctx, wire)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := record.Body()
	nonce, _ := body.Field("nonce").ByteString()
	if nonce[0] != 2 {
		t.Fatal("candidate was replaced on capacity retry")
	}
	record.Release()
	cancel()
	waitRuntime(t, done)
}

func TestSessionRuntimeRetainsPongProviderFailure(t *testing.T) {
	local := newOpenEndpoint(t, 0, 2, 2, 1)
	peer := newOpenEndpoint(t, 1, 2, 2, 1)
	failure := errors.New("original provider failure")
	local.maintenance, _ = NewRecordWriter(local.engine, 0, idleWriterFunc(func([]byte) (int, error) { return 0, failure }))
	maintenanceMessages(t, local, 2, 4)
	reader, writer := io.Pipe()
	defer writer.Close()
	f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: reader, interrupt: func() { _ = reader.Close() }}, false)
	r := f.startOwner(t)
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	if _, err := peer.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(peer.control.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := waitRuntime(t, done); !errors.Is(err, failure) {
		t.Fatal("close notification erased provider failure", err)
	}
}

// Synthetic shared test backing verifies owner identity and exact reservations;
// it makes no claim about production allocator or provider qualification.
func backgroundResources(t *testing.T, endpoint *openEndpoint) *nativeAssemblyFixture {
	t.Helper()
	if endpoint.background != nil {
		return endpoint.background
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 32, ReferenceSlots: 64}
	config.Limit = resourcev4.Vector{resourcev4.SDKBytes: 4 << 20, resourcev4.Items: 512, resourcev4.WorkSlots: 64, resourcev4.Tasks: 64, resourcev4.Timers: 64}
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.background = &nativeAssemblyFixture{root: root}
	t.Cleanup(root.Close)
	return endpoint.background
}

func TestSessionRuntimeCleanupIncludesManualProbeProviderTail(t *testing.T) {
	local := newOpenEndpoint(t, 0, 2, 2, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	local.maintenance, _ = NewRecordWriter(local.engine, 0, idleWriterFunc(func(data []byte) (int, error) { close(entered); <-release; return len(data), nil }))
	p := testLiveness(t, local, 2)
	reader, writer := io.Pipe()
	defer writer.Close()
	f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: reader, interrupt: func() { _ = reader.Close() }}, false)
	r := f.startOwner(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	probe := testProbe(t, p, 1000)
	defer probe.Release()
	published := make(chan error, 1)
	go func() { _, err := probe.Publish(context.Background()); published <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("manual probe did not publish")
	}
	cancel()
	waitRuntime(t, done)
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := r.WaitCleanup(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("manual provider tail was detached", err)
	}
	if err := r.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("manual tail reservation retired early", err)
	}
	once.Do(func() { close(release) })
	waitRuntime(t, published)
	cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
	defer end()
	if err := r.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRuntimeNewOpenGetsNewOriginalDeadline(t *testing.T) {
	local, peer, now := idleEndpoints(t, 0)
	f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: bytes.NewReader(nil)}, false)
	f.config.DispatchTimeoutMS = 10
	r := f.startOwner(t)
	for _, at := range []uint64{0, 50} {
		now.Store(at)
		var wire bytes.Buffer
		_, _, err := peer.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, peer.reservation(&wire, 8), streamTestDeadline(t, peer.engine))
		if err != nil {
			t.Fatal(err)
		}
		record, err := f.config.SharedIngress.Read(context.Background(), &wire)
		if err != nil {
			t.Fatal(err)
		}
		deadline, err := r.dispatchDeadline(record)
		if err == nil {
			err = f.config.SharedIngress.Dispatch(context.Background(), record, deadline)
		}
		record.Release()
		if err != nil {
			t.Fatal("new OPEN inherited an expired earlier deadline", at, err)
		}
		if remaining, err := deadline.RemainingMS(); err != nil || remaining > 10 || remaining == 0 {
			t.Fatal(remaining, err)
		}
	}
}
