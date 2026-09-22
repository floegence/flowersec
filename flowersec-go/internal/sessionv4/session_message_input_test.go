package sessionv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type sessionMessageProvider struct {
	read                  func(context.Context, []byte) (int, error)
	write                 func(context.Context, []byte) error
	close                 func() error
	reads, writes, closes atomic.Int32
}

func (p *sessionMessageProvider) ReadMessage(ctx context.Context, dst []byte) (int, error) {
	p.reads.Add(1)
	return p.read(ctx, dst)
}
func (p *sessionMessageProvider) WriteMessage(ctx context.Context, wire []byte) error {
	p.writes.Add(1)
	if p.write != nil {
		return p.write(ctx, wire)
	}
	return nil
}
func (p *sessionMessageProvider) Close() error {
	p.closes.Add(1)
	if p.close != nil {
		return p.close()
	}
	return nil
}

func messageInputReservations(t *testing.T, charge resourcev4.Vector) (*resourcev4.Root, resourcev4.Reference, resourcev4.Reference) {
	t.Helper()
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 2, ReservationSlots: 4, ReferenceSlots: 8}
	backing, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit = charge
	config.Limit[resourcev4.SDKBytes] += backing + 1024
	config.Limit[resourcev4.Items]++
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	owner := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	owner.Instance, owner.Backing = [16]byte{2}, [16]byte{2}
	ref, err := root.Reserve(owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	t.Cleanup(environment.Release)
	t.Cleanup(ref.Release)
	return root, ref, environment
}

func messageInputFixture(t *testing.T, parent context.Context, provider *sessionMessageProvider) (*SessionMessageInput, *resourcev4.Root, resourcev4.Reference) {
	t.Helper()
	options := SessionMessageInputOptions{MaxFrame: 128, WriteSlots: 4, RuntimeBytes: 16384}
	charge, err := SessionMessageInputCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	root, ref, environment := messageInputReservations(t, charge)
	m, err := NewSessionMessageInput(parent, provider, options, ref, environment)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Check() == nil {
		t.Fatal("adapter did not take its unique reservation")
	}
	t.Cleanup(func() {
		_ = m.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := m.WaitCleanup(ctx); err != nil {
			t.Error("message adapter retained a provider tail", err)
		} else if err := m.Retire(); err != nil {
			t.Error(err)
		}
	})
	return m, root, environment
}

func messageEnvelope(t *testing.T, frame protocolv4.FrameType, size int) []byte {
	t.Helper()
	// The adapter checks framing; authentication remains the original receiver.
	wire, err := (protocolv4.Envelope{FrameType: frame, Payload: bytes.Repeat([]byte{7}, size)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func awaitMessage(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("message provider did not reach the original call")
	}
}

func awaitMessageWriters(t *testing.T, m *SessionMessageInput, count uint32) {
	t.Helper()
	limit := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		writers := m.writers
		m.mu.Unlock()
		if writers == count {
			return
		}
		if time.Now().After(limit) {
			t.Fatal("original writer did not enter its bounded position", writers, count)
		}
		runtime.Gosched()
	}
}

func TestSessionMessageInputValidatesBeforeExposingAnyBytes(t *testing.T) {
	valid := messageEnvelope(t, protocolv4.FrameStreamData, 40)
	for _, fault := range []string{"empty", "short", "split", "trailing", "concatenated", "prefix_length", "flags", "unknown", "initial_type", "oversize", "bad_count"} {
		t.Run(fault, func(t *testing.T) {
			wire := bytes.Clone(valid)
			switch fault {
			case "empty":
				wire = nil
			case "short":
				wire = wire[:7]
			case "split":
				wire = wire[:20]
			case "trailing":
				wire = append(wire, 0)
			case "concatenated":
				wire = append(wire, valid...)
			case "prefix_length":
				binary.BigEndian.PutUint32(wire[:4], math.MaxUint32)
			case "flags":
				wire[5] = 1
			case "unknown":
				wire[4] = 255
			case "initial_type":
				wire[4] = byte(protocolv4.FrameReady)
			case "oversize":
				wire = messageEnvelope(t, protocolv4.FrameStreamData, 129)
			}
			p := &sessionMessageProvider{read: func(_ context.Context, dst []byte) (int, error) {
				if len(dst) != 136 || cap(dst) != 136 {
					t.Error("provider did not receive the precharged exact buffer")
				}
				if fault == "bad_count" {
					return len(dst) + 1, nil
				}
				if len(wire) > len(dst) {
					return 0, io.ErrShortBuffer
				}
				return copy(dst, wire), nil
			}}
			m, _, _ := messageInputFixture(t, context.Background(), p)
			dst := bytes.Repeat([]byte{0x55}, 8)
			if n, err := m.Read(dst); n != 0 || err == nil || !bytes.Equal(dst, bytes.Repeat([]byte{0x55}, 8)) {
				t.Fatal("invalid message exposed a prefix", n, err)
			}
			if _, err := m.Read(dst); err == nil || p.reads.Load() != 1 {
				t.Fatal("failed message borrowed bytes from a later message", err)
			}
		})
	}
}

func TestSessionMessageInputPreservesOneEnvelopePerMessage(t *testing.T) {
	first, second := messageEnvelope(t, protocolv4.FrameStreamData, 40), messageEnvelope(t, protocolv4.FramePing, 48)
	messages := [][]byte{first, second}
	p := &sessionMessageProvider{read: func(_ context.Context, dst []byte) (int, error) {
		wire := messages[0]
		messages = messages[1:]
		return copy(dst, wire), nil
	}}
	m, _, _ := messageInputFixture(t, context.Background(), p)
	if n, err := m.Read(nil); n != 0 || err != nil || p.reads.Load() != 0 {
		t.Fatal("zero read consumed a message", n, err)
	}
	out := make([]byte, len(first))
	if _, err := io.ReadFull(m, out[:8]); err != nil || p.reads.Load() != 1 {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(m, out[8:]); err != nil || !bytes.Equal(out, first) || p.reads.Load() != 1 {
		t.Fatal("one message did not preserve its full envelope", err)
	}
	large := make([]byte, 512)
	if n, err := m.Read(large); err != nil || n != len(second) || !bytes.Equal(large[:n], second) || p.reads.Load() != 2 {
		t.Fatal("read combined message boundaries", n, err)
	}
	if n, err := m.Write(nil); n != 0 || err != nil || p.writes.Load() != 0 {
		t.Fatal("zero write published an empty message", n, err)
	}
	if n, err := m.Write(first); n != len(first) || err != nil || p.writes.Load() != 1 {
		t.Fatal("complete write was split", n, err)
	}
	if n, err := m.Write(append(bytes.Clone(first), second...)); n != 0 || !errors.Is(err, ErrSessionMessageFraming) || p.writes.Load() != 1 {
		t.Fatal("concatenated write reached provider", n, err)
	}
}

func TestSessionMessageInputInitialCapsAndCanceledHandoffContext(t *testing.T) {
	initial := messageEnvelope(t, protocolv4.FrameNegotiate, 512)
	runtimeWire := messageEnvelope(t, protocolv4.FramePing, 40)
	p := &sessionMessageProvider{read: func(_ context.Context, dst []byte) (int, error) {
		if len(dst) != len(initial) {
			return 0, io.ErrShortBuffer
		}
		return copy(dst, initial), nil
	}}
	m, _, _ := messageInputFixture(t, context.Background(), p)
	for range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		dst := make([]byte, len(initial))
		if n, err := m.ReadMessage(ctx, dst); n != len(initial) || err != nil || !bytes.Equal(dst, initial) {
			cancel()
			t.Fatal("runtime cap was applied to separately reserved initial input", n, err)
		}
		if err := m.WriteMessage(ctx, initial); err != nil {
			cancel()
			t.Fatal("runtime cap was applied to initial output", err)
		}
		cancel() // Successful READY cancels this original, now detached context.
		if n, err := m.Write(runtimeWire); n != len(runtimeWire) || err != nil {
			t.Fatal("old initial cancellation closed the transferred runtime", n, err)
		}
	}
	if p.closes.Load() != 0 {
		t.Fatal("initial handoff closed the provider")
	}
}

func TestSessionMessageInputSerializesOriginalWriterPositions(t *testing.T) {
	first, second := messageEnvelope(t, protocolv4.FrameStreamData, 40), messageEnvelope(t, protocolv4.FramePing, 48)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var active, maximum atomic.Int32
	var mu sync.Mutex
	var output [][]byte
	p := &sessionMessageProvider{write: func(_ context.Context, wire []byte) error {
		current := active.Add(1)
		defer active.Add(-1)
		if current > maximum.Load() {
			maximum.Store(current)
		}
		mu.Lock()
		output = append(output, bytes.Clone(wire))
		first := len(output) == 1
		mu.Unlock()
		if first {
			close(entered)
			<-release
		}
		return nil
	}}
	m, _, _ := messageInputFixture(t, context.Background(), p)
	results := make(chan error, 2)
	go func() { _, err := m.Write(first); results <- err }()
	awaitMessage(t, entered)
	go func() { _, err := m.Write(second); results <- err }()
	awaitMessageWriters(t, m, 2)
	if p.writes.Load() != 1 {
		t.Fatal("second provider write entered before whole-message completion")
	}
	releaseOnce.Do(func() { close(release) })
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal("admitted writer was spuriously rejected", err)
		}
	}
	if maximum.Load() != 1 || len(output) != 2 || !bytes.Equal(output[0], first) || !bytes.Equal(output[1], second) {
		t.Fatal("whole-envelope order or serialization changed")
	}
}

func TestSessionMessageInputCleanupWaitsForCloseAndAllMethodTails(t *testing.T) {
	wire := messageEnvelope(t, protocolv4.FramePing, 40)
	readEntered, writeEntered, closeEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
	readRelease, writeRelease, closeRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var readOnce, writeOnce, closeOnce sync.Once
	defer readOnce.Do(func() { close(readRelease) })
	defer writeOnce.Do(func() { close(writeRelease) })
	defer closeOnce.Do(func() { close(closeRelease) })
	var sourceContext context.Context
	p := &sessionMessageProvider{
		read: func(ctx context.Context, dst []byte) (int, error) {
			sourceContext = ctx
			close(readEntered)
			<-readRelease
			return copy(dst, wire), nil
		},
		write: func(context.Context, []byte) error { close(writeEntered); <-writeRelease; return nil },
		close: func() error { close(closeEntered); <-closeRelease; return nil },
	}
	m, root, environment := messageInputFixture(t, context.Background(), p)
	readResult, queuedResult := make(chan error, 1), make(chan error, 1)
	type writeResult struct {
		n   int
		err error
	}
	written := make(chan writeResult, 1)
	go func() { _, err := m.Read(make([]byte, 8)); readResult <- err }()
	awaitMessage(t, readEntered)
	go func() { n, err := m.Write(wire); written <- writeResult{n, err} }()
	awaitMessage(t, writeEntered)
	go func() { _, err := m.Write(wire); queuedResult <- err }()
	awaitMessageWriters(t, m, 2)
	before := root.Snapshot().Charged
	alias := *m
	alias.InterruptRead()
	awaitMessage(t, closeEntered)
	select {
	case <-sourceContext.Done():
	default:
		t.Fatal("provider Close began before call-context cancellation")
	}
	if err := <-queuedResult; !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("waiting writer was not canceled", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checkPending := func() {
		t.Helper()
		if !errors.Is(m.WaitCleanup(ctx), context.Canceled) || !errors.Is(m.Retire(), cryptov4.ErrCapacity) || root.Snapshot().Charged != before {
			t.Fatal("unsettled original provider tail lost its quota")
		}
	}
	checkPending()
	closeOnce.Do(func() { close(closeRelease) })
	checkPending()
	readOnce.Do(func() { close(readRelease) })
	if err := <-readResult; !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("late input escaped close", err)
	}
	checkPending()
	writeOnce.Do(func() { close(writeRelease) })
	result := <-written
	if result.n != len(wire) || !errors.Is(result.err, cryptov4.ErrClosed) {
		t.Fatal("late complete handoff lost its actual byte count", result)
	}
	joined, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := m.WaitCleanup(joined); err != nil || root.Snapshot().Charged != before {
		t.Fatal("cleanup refunded before explicit retirement", err)
	}
	environment.Release()
	if root.Snapshot().Reservations != 2 {
		t.Fatal("shared dependency disappeared before original retirement")
	}
	if m.Retire() != nil || alias.Retire() != nil || root.Snapshot().Reservations != 0 || p.closes.Load() != 1 || p.writes.Load() != 1 {
		t.Fatal("aliases duplicated provider close or reservation release")
	}
	if m.buffer != nil || m.provider != nil || m.parent != nil || m.readContext != nil || m.writeContext != nil {
		t.Fatal("cleanup retained input/provider/context graph")
	}
}

func TestSessionMessageInputPropagatesOriginalCallCancellation(t *testing.T) {
	entered := make(chan struct{})
	var observed context.Context
	p := &sessionMessageProvider{read: func(ctx context.Context, _ []byte) (int, error) {
		observed = ctx
		close(entered)
		<-ctx.Done()
		return 0, ctx.Err()
	}}
	m, _, _ := messageInputFixture(t, context.Background(), p)
	parent := &runtimeOpaqueContext{done: make(chan struct{}), reason: context.DeadlineExceeded}
	result := make(chan error, 1)
	go func() { _, err := m.ReadMessage(parent, make([]byte, 520)); result <- err }()
	awaitMessage(t, entered)
	parent.cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(context.Cause(observed), context.DeadlineExceeded) {
			t.Fatal("original call cancellation cause changed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider context did not observe original cancellation")
	}
	if parent.valueCalls.Load() != 0 {
		t.Fatal("SDK installed hidden standard-library context propagation")
	}
}

func TestSessionMessageInputAdmissionFailsBeforeProviderOwnership(t *testing.T) {
	options := SessionMessageInputOptions{MaxFrame: 128, WriteSlots: 4, RuntimeBytes: 16384}
	charge, err := SessionMessageInputCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SessionMessageInputCharge(SessionMessageInputOptions{MaxFrame: 128, WriteSlots: 4, RuntimeBytes: math.MaxUint64}); err == nil {
		t.Fatal("overflowing runtime charge accepted")
	}
	charge[resourcev4.SDKBytes]--
	root, ref, environment := messageInputReservations(t, charge)
	p := &sessionMessageProvider{}
	before := root.Snapshot()
	if m, err := NewSessionMessageInput(context.Background(), p, options, ref, environment); m != nil || !errors.Is(err, resourcev4.ErrCapacity) || root.Snapshot() != before || ref.Check() != nil {
		t.Fatal("insufficient admission consumed original owner", err)
	}
	_, _, foreign := messageInputReservations(t, charge)
	if m, err := NewSessionMessageInput(context.Background(), p, options, ref, foreign); m != nil || !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("private root bypassed original Environment", err)
	}
	if p.closes.Load() != 0 || p.reads.Load() != 0 || p.writes.Load() != 0 {
		t.Fatal("failed constructor took provider ownership")
	}
	borrow, err := environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	before = root.Snapshot()
	if m, err := NewSessionMessageInputWithEnvironmentBorrow(context.Background(), p, options, ref, borrow); m != nil || !errors.Is(err, resourcev4.ErrCapacity) || root.Snapshot() != before || borrow.Check() != nil {
		t.Fatal("failed preadmission consumed caller's preborrow", err)
	}
}

func TestSessionMessageInputUsesPreadmittedEnvironmentBorrowWithoutAnotherSlot(t *testing.T) {
	options := SessionMessageInputOptions{MaxFrame: 128, WriteSlots: 4, RuntimeBytes: 16384}
	charge, err := SessionMessageInputCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	root, ref, environment := messageInputReservations(t, charge)
	borrow, err := environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	var others []resourcev4.Reference
	for {
		next, err := environment.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		others = append(others, next)
		defer next.Release()
	}
	p := &sessionMessageProvider{}
	before := root.Snapshot()
	if m, err := NewSessionMessageInput(context.Background(), p, options, ref, environment); m != nil || !errors.Is(err, resourcev4.ErrCapacity) || ref.Check() != nil {
		t.Fatal("normal construction invented another reference slot", err)
	}
	m, err := NewSessionMessageInputWithEnvironmentBorrow(context.Background(), p, options, ref, borrow)
	if err != nil || root.Snapshot().References != before.References || borrow.Check() == nil {
		t.Fatal("preadmitted borrow was not moved in place", err)
	}
	borrow.Release() // The stale plan handle cannot release the adapter's owner.
	_ = m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.WaitCleanup(ctx); err != nil || m.Retire() != nil {
		t.Fatal(err)
	}
	for _, other := range others {
		other.Release()
	}
	environment.Release()
	if root.Snapshot().Reservations != 0 || p.closes.Load() != 1 {
		t.Fatal("preborrowed adapter did not release original ownership")
	}
}
