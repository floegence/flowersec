package sessionv4

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// This lifecycle belongs to the synthetic provider, independently of the
// prepared/admission owner. Optional gates expose the original physical tails.
type preparedTestProvider struct {
	closes, waits, retires, reads, writes atomic.Int32
	closeEntered, closeRelease            chan struct{}
	readEntered, readRelease              chan struct{}
	waitEntered, waitRelease              chan struct{}
	waitOnce                              sync.Once
	retireFailure                         atomic.Bool
	closeError                            error
	environment                           resourcev4.Reference
}

func (p *preparedTestProvider) CheckEnvironment(environment resourcev4.Reference) error {
	return p.environment.CheckSameEnvironment(environment)
}

func (p *preparedTestProvider) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	g, _ := protocolv4.ConnectionAssurance("native_websocket_tls13")
	return g, nil
}

func (p *preparedTestProvider) Read(dst []byte) (int, error) {
	p.reads.Add(1)
	if p.readEntered != nil {
		close(p.readEntered)
		<-p.readRelease
	}
	return copy(dst, "original"), io.EOF
}
func (p *preparedTestProvider) Write(src []byte) (int, error) {
	p.writes.Add(1)
	return len(src), nil
}
func (p *preparedTestProvider) ReadMessage(_ context.Context, dst []byte) (int, error) {
	return p.Read(dst)
}
func (p *preparedTestProvider) WriteMessage(_ context.Context, src []byte) error {
	_, err := p.Write(src)
	return err
}
func (p *preparedTestProvider) Close() error {
	p.closes.Add(1)
	if p.closeEntered != nil {
		close(p.closeEntered)
		<-p.closeRelease
	}
	return p.closeError
}
func (p *preparedTestProvider) WaitCleanup(ctx context.Context) error {
	p.waits.Add(1)
	if p.waitEntered != nil {
		p.waitOnce.Do(func() { close(p.waitEntered) })
		select {
		case <-p.waitRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func (p *preparedTestProvider) Retire() error {
	p.retires.Add(1)
	if p.retireFailure.Load() {
		return resourcev4.ErrOwner
	}
	return nil
}

func preparedTestConfig(t *testing.T) (PreparedCarrierConfig, *resourcev4.Root) {
	t.Helper()
	clock := sessionTestClock(t)
	deadline, err := timev4.NewAge(clock, 10000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	charge, err := PreparedCarrierCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 2, ReservationSlots: 4, ReferenceSlots: 8}
	backing, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit = charge
	config.Limit[resourcev4.SDKBytes] += backing + 128
	config.Limit[resourcev4.Items] += 2
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	key := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := root.Reserve(key, resourcev4.Vector{resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environment.Release)
	key.Instance, key.Backing = [16]byte{2}, [16]byte{2}
	reservation, err := root.Reserve(key, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reservation.Release)
	return PreparedCarrierConfig{Candidate: protocolv4.PoolMember{CandidateID: [16]byte{3}, RouteDigest: [32]byte{4}}, Attempt: [16]byte{5},
		Session: testSessionContract(t, protocolv4.DHProfileX25519, "transport", 4096, 4, 0, ^uint64(0)),
		Role:    protocolv4.ClientToServer, Deadline: deadline, Reservation: reservation, Environment: environment, RuntimeBytes: 4096}, root
}

func cleanupPreparedTest(t *testing.T, p *PreparedCarrier) {
	t.Helper()
	t.Cleanup(func() {
		_ = p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	})
}

func TestPreparedCarrierImmutableBindingAndOnceActivation(t *testing.T) {
	for _, messages := range []bool{false, true} {
		t.Run(map[bool]string{false: "stream", true: "messages"}[messages], func(t *testing.T) {
			config, root := preparedTestConfig(t)
			provider := &preparedTestProvider{environment: config.Environment}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var p *PreparedCarrier
			var err error
			if messages {
				p, err = NewPreparedMessages(ctx, config, provider)
			} else {
				p, err = NewPreparedStream(ctx, config, provider)
			}
			if err != nil {
				t.Fatal(err)
			}
			cleanupPreparedTest(t, p)
			if _, exposed := any(p).(io.ReadWriteCloser); exposed {
				t.Fatal("prepared handle exposed unactivated stream I/O")
			}
			if _, exposed := any(p).(InitialMessages); exposed {
				t.Fatal("prepared handle exposed unactivated message I/O")
			}
			want := p.AdmissionBinding()
			config.Candidate.CandidateID[0]++
			detached := p.AdmissionBinding()
			detached.Attempt[0]++
			if p.AdmissionBinding() != want || want.MessageCarrier != messages {
				t.Fatal("caller changed captured provider binding")
			}
			admission, other := &SessionAdmissionReservation{}, &SessionAdmissionReservation{}
			if _, _, err := p.activate(admission); !errors.Is(err, resourcev4.ErrOwner) {
				t.Fatal("unbound owner activated", err)
			}
			if err := p.bindAdmission(admission); err != nil {
				t.Fatal(err)
			}
			if err := p.bindAdmission(other); !errors.Is(err, cryptov4.ErrTransition) {
				t.Fatal("another admission rebound original winner", err)
			}
			if _, _, err := p.activate(other); !errors.Is(err, resourcev4.ErrOwner) {
				t.Fatal("another admission took original I/O", err)
			}
			before := root.Snapshot().Charged
			stream, message, err := p.activate(admission)
			if err != nil || (message != nil) != messages || (stream != nil) == messages {
				t.Fatal("wrong carrier handoff", err)
			}
			cancel()
			config.Deadline.Cancel()
			if messages {
				err = message.WriteMessage(context.Background(), []byte("original"))
			} else {
				_, err = stream.Write([]byte("original"))
			}
			if err != nil || provider.writes.Load() != 1 {
				t.Fatal("prepare cancellation revoked transferred Session I/O", err)
			}
			copied := *p
			if _, _, err := copied.activate(admission); !errors.Is(err, cryptov4.ErrTransition) {
				t.Fatal("copied handle activated twice", err)
			}
			if err := p.closeActivated(admission); err != nil {
				t.Fatal(err)
			}
			if messages {
				err = message.Close()
			} else {
				err = stream.Close()
			}
			if err != nil || provider.closes.Load() != 1 {
				t.Fatal("initial and cleanup owners duplicated physical Close", err)
			}
			if err := copied.WaitCleanup(context.Background()); err != nil || root.Snapshot().Charged != before {
				t.Fatal("cleanup returned wrapper charge before retirement", err)
			}
			if err := p.Retire(); err != nil {
				t.Fatal(err)
			}
			after := root.Snapshot()
			if err := copied.Retire(); err != nil || root.Snapshot() != after || provider.retires.Load() != 1 {
				t.Fatal("copied retirement repeated physical refund", err)
			}
		})
	}
}

func TestPreparedCarrierOriginalEnvironmentAndConstructorFailureOwnership(t *testing.T) {
	config, root := preparedTestConfig(t)
	foreign, _ := preparedTestConfig(t)
	provider := &preparedTestProvider{environment: config.Environment}
	before := root.Snapshot()
	provider.environment = foreign.Environment
	if p, err := NewPreparedMessages(context.Background(), config, provider); p != nil || !errors.Is(err, resourcev4.ErrOwner) || root.Snapshot() != before || provider.closes.Load() != 0 {
		t.Fatal("foreign provider wrapped in local Environment", err)
	}
	provider.environment = config.Environment
	bad := config
	bad.Environment = foreign.Environment
	if _, err := NewPreparedMessages(context.Background(), bad, provider); !errors.Is(err, resourcev4.ErrOwner) || root.Snapshot() != before || provider.closes.Load() != 0 || config.Reservation.Check() != nil {
		t.Fatal("foreign Environment consumed provider or reservation", err)
	}
	if _, err := NewPreparedStream(context.Background(), config, &initialMemoryStream{}); !errors.Is(err, cryptov4.ErrConfiguration) || root.Snapshot() != before {
		t.Fatal("provider without physical cleanup was adopted", err)
	}
	bad = config
	bad.RuntimeBytes = math.MaxUint64
	if _, err := NewPreparedMessages(context.Background(), bad, provider); !errors.Is(err, cryptov4.ErrConfiguration) || root.Snapshot() != before {
		t.Fatal("invalid charge consumed original ownership", err)
	}
	p, err := NewPreparedMessages(context.Background(), config, provider)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, p)
	if err := p.CheckEnvironment(config.Environment); err != nil {
		t.Fatal(err)
	}
	alias, err := config.Environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	if err := p.CheckEnvironment(alias); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("same backing alias replaced original Environment identity", err)
	}
	current, err := config.Environment.Take(resourcev4.Vector{resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer current.Release()
	if err := p.CheckEnvironment(current); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("later Environment generation replaced original", err)
	}
	if err := p.Check(); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("stale original Environment admitted activation", err)
	}
}

func TestPreparedCarrierCancellationAndDeadlineCannotReactivate(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "context", true: "deadline"}[deadline], func(t *testing.T) {
			config, _ := preparedTestConfig(t)
			provider := &preparedTestProvider{environment: config.Environment}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p, err := NewPreparedMessages(ctx, config, provider)
			if err != nil {
				t.Fatal(err)
			}
			cleanupPreparedTest(t, p)
			admission := &SessionAdmissionReservation{}
			if err := p.bindAdmission(admission); err != nil {
				t.Fatal(err)
			}
			if deadline {
				config.Deadline.Cancel()
			} else {
				cancel()
			}
			_, _, first := p.activate(admission)
			if first == nil || p.Check() != first || provider.closes.Load() != 0 {
				t.Fatal("invalid preparation revived or ran a callback under the gate", first)
			}
		})
	}
}

func TestPreparedCarrierPinsNoncooperativeCloseAndPhysicalCleanup(t *testing.T) {
	config, root := preparedTestConfig(t)
	provider := &preparedTestProvider{environment: config.Environment, closeEntered: make(chan struct{}), closeRelease: make(chan struct{}), waitEntered: make(chan struct{}), waitRelease: make(chan struct{})}
	releaseClose := sync.OnceFunc(func() { close(provider.closeRelease) })
	releaseWait := sync.OnceFunc(func() { close(provider.waitRelease) })
	defer releaseClose()
	defer releaseWait()
	p, err := NewPreparedMessages(context.Background(), config, provider)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, p)
	before := root.Snapshot().Charged
	if err := p.Close(); err != nil || provider.closes.Load() != 0 {
		t.Fatal("logical Close invoked potentially blocking provider", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- p.WaitCleanup(ctx) }()
	<-provider.closeEntered
	cancel()
	if err := p.Retire(); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("blocking Close was retired", err)
	}
	if err := p.WaitCleanup(context.Background()); !errors.Is(err, cryptov4.ErrCapacity) || root.Snapshot().Charged != before {
		t.Fatal("second cleanup escaped bounded observer or refunded tail", err)
	}
	releaseClose()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if root.Snapshot().Charged != before || provider.closes.Load() != 1 {
		t.Fatal("canceled cleanup lost provider ownership")
	}
	releaseWait()
	if err := p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	provider.retireFailure.Store(true)
	if err := p.Retire(); !errors.Is(err, resourcev4.ErrOwner) || root.Snapshot().Charged != before {
		t.Fatal("failed original provider retirement refunded wrapper", err)
	}
	provider.retireFailure.Store(false)
	if err := p.Retire(); err != nil || provider.closes.Load() != 1 {
		t.Fatal(err)
	}
}

func TestPreparedCarrierCloseErrorDoesNotPreventActualRetirement(t *testing.T) {
	config, root := preparedTestConfig(t)
	want := errors.New("original provider close failed after shutdown")
	provider := &preparedTestProvider{environment: config.Environment, closeError: want}
	p, err := NewPreparedMessages(context.Background(), config, provider)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, p)
	before := root.Snapshot().Charged
	if err := p.WaitCleanup(context.Background()); err != nil || p.CloseError() != want {
		t.Fatal("close result replaced physical cleanup state", err, p.CloseError())
	}
	if err := p.WaitCleanup(context.Background()); err != nil || root.Snapshot().Charged != before {
		t.Fatal("observing cleanup changed original ownership", err)
	}
	if err := p.Retire(); err != nil || provider.retires.Load() != 1 {
		t.Fatal("close error leaked a completed original provider", err)
	}
	charge, _ := PreparedCarrierCharge(config.RuntimeBytes)
	after := root.Snapshot().Charged
	for dimension := range before {
		if before[dimension]-after[dimension] != charge[dimension] {
			t.Fatalf("retirement did not refund dimension %d", dimension)
		}
	}
	if p.CloseError() != want {
		t.Fatal("retirement erased the original diagnostic cause")
	}
}

func TestPreparedCarrierRetainsAdapterUntilOriginalReadReturns(t *testing.T) {
	config, root := preparedTestConfig(t)
	provider := &preparedTestProvider{environment: config.Environment, readEntered: make(chan struct{}), readRelease: make(chan struct{})}
	release := sync.OnceFunc(func() { close(provider.readRelease) })
	defer release()
	p, err := NewPreparedStream(context.Background(), config, provider)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, p)
	admission := &SessionAdmissionReservation{}
	if err := p.bindAdmission(admission); err != nil {
		t.Fatal(err)
	}
	stream, _, err := p.activate(admission)
	if err != nil {
		t.Fatal(err)
	}
	before := root.Snapshot().Charged
	finished := make(chan error, 1)
	go func() {
		var dst [16]byte
		n, err := stream.Read(dst[:])
		if n != len("original") || string(dst[:n]) != "original" {
			err = errors.New("original read progress lost")
		}
		finished <- err
	}()
	<-provider.readEntered
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("concurrent read entered same provider", err)
	}
	if err := p.WaitCleanup(context.Background()); !errors.Is(err, cryptov4.ErrCapacity) || root.Snapshot().Charged != before {
		t.Fatal("provider cleanup hid original read callback tail", err)
	}
	if err := p.Retire(); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("retired in-flight adapter", err)
	}
	release()
	if err := <-finished; !errors.Is(err, io.EOF) {
		t.Fatal("close rewrote the original read result", err)
	}
	if err := p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}
