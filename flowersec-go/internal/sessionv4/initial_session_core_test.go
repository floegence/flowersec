package sessionv4

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type initialCoreFixture struct {
	root        *resourcev4.Root
	plan        *SessionCorePlan
	environment resourcev4.Reference
	next        byte
	scope       SessionResourceScope
	limit       resourcev4.Vector
}

func (f *initialCoreFixture) reserve(t *testing.T, charge resourcev4.Vector) resourcev4.Reference {
	t.Helper()
	f.next++
	ref, err := f.root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{2}, Backing: [16]byte{f.next}, Kind: 1000}, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	return ref
}

func initialCorePrepare(t *testing.T, fixtures *[2]initialCoreFixture) func(*cryptov4.HandshakeConfig, *InitialConfig) {
	return initialCorePrepareCarrier(t, fixtures, false)
}

func initialCorePrepareCarrier(t *testing.T, fixtures *[2]initialCoreFixture, messages bool) func(*cryptov4.HandshakeConfig, *InitialConfig) {
	return initialCorePrepareConfig(t, fixtures, messages, nil)
}

func initialCorePrepareConfig(t *testing.T, fixtures *[2]initialCoreFixture, messages bool, configure func(*SessionCoreConfig)) func(*cryptov4.HandshakeConfig, *InitialConfig) {
	return func(h *cryptov4.HandshakeConfig, initial *InitialConfig) {
		f := &fixtures[h.Role]
		cfg := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 8, ReservationSlots: 256, ReferenceSlots: 512,
			Limit: resourcev4.Vector{resourcev4.SDKBytes: 64 << 20, resourcev4.Items: 4096, resourcev4.Tasks: 256, resourcev4.WorkSlots: 256, resourcev4.Timers: 64, resourcev4.Sessions: 2}}
		backing, err := resourcev4.BackingBytes(cfg)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Limit[resourcev4.SDKBytes] += backing
		f.root, err = resourcev4.NewRoot(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.root.Close)
		f.limit = cfg.Limit
		f.scope = corePlanTestScope(t, f.root, cfg.Limit, 1)
		environment := f.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 1 << 20, resourcev4.Items: 1})
		f.environment = environment
		charge, err := InitialCharge(initial.Limits)
		if err != nil {
			t.Fatal(err)
		}
		initial.Reservation.Release()
		initial.Reservation = f.reserve(t, charge)
		plan := SessionCoreConfig{Session: h.Session, Clock: h.Clock, MaxScopes: 4, PendingScopes: 2, WorkSlots: 4,
			Open:        OpenLimits{Active: 2, Opening: 2, Terminal: 7, RejectionReserve: 1, IngressItems: 2, IngressBytes: 64 << 10, PerClass: [3]uint32{2}, PerOpener: [2][3]uint32{{2}, {2}}, Lifetime: [2][3]uint64{{1024}, {1024}}},
			Maintenance: cryptov4.MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}, EngineResources: cryptov4.EngineResourceOptions{RuntimeBytes: 64 << 10}, RuntimeBytes: 1 << 20,
			DecoderNodes: 128, MaxDataPayloadBytes: 1024, SendWorkers: [3]uint32{1}, ProbeSlots: 2, PongSlots: 2, RekeyWaitSlots: 2,
			Automatic: AutomaticLivenessPolicy{1000000, 1000, 1000, 3}, Messages: MaintenanceMessagePolicy{8, 1000, 10000},
			Termination: StreamTerminationPolicy{10000, 1000, 8}, Rekey: RekeyPhaseBudgets{5000, 10000, 30000},
			SharedDiscard: SharedDiscardPolicy{16, 65536, 10000}, DispatchTimeoutMS: 10000, RetirementTimeoutMS: 10000}
		plan.MessageCarrier = messages
		if messages {
			plan.MessageRuntimeBytes = 64 << 10
		}
		if configure != nil {
			configure(&plan)
		}
		f.plan, err = NewSessionCorePlan(plan, f.root, resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{3}, Backing: [16]byte{1}, Kind: 2}, environment, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := f.plan.Abort(ctx); err != nil {
				t.Error(err)
			}
		})
	}
}

func (f *initialCoreFixture) streamReservation(t *testing.T, core *SessionCore) StreamReservation {
	t.Helper()
	charge, err := ReceivePoolCharge(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewReceivePool(core.Engine().SessionParameters().Contract.Limits().MaxCredit, 64, 1, f.reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	send, err := SendFlowCharge(64)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := SendQueueCharge(64, 2)
	if err != nil {
		t.Fatal(err)
	}
	return StreamReservation{Pool: pool, ReceiveCapacity: 64, SendCapacity: 64, SendReservation: f.reserve(t, send),
		OpenStorage: make([]byte, 128), Writer: core.Writer(), MaxPlaintext: 128, InitialReceiveLimit: 64,
		SendQueue: &SendQueueReservation{Capacity: 64, Waiters: 2, Chunk: 64, Reservation: f.reserve(t, queue)}}
}

func waitCoreOpen(t *testing.T, a *OpenAdmission, h OpenHandle, pending bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		a.mu.Lock()
		s, err := a.slot(h)
		ready := err == nil && ((pending && s.phase == openPending) || (!pending && s.accepted))
		a.mu.Unlock()
		if ready {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("original OPEN did not reach its expected outcome")
}

func TestInitialCoreRunsBothReadyAndDuplexStreamOnOriginalCarrier(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		for _, framing := range []string{"stream", "messages"} {
			t.Run(profile+"/"+framing, func(t *testing.T) {
				var fixtures [2]initialCoreFixture
				pair, configs := initialTestPairPrepared(t, profile, framing, 4, initialCorePrepareCarrier(t, &fixtures, framing == "messages"))
				var cores [2]*SessionCore
				results := make(chan error, 2)
				for role := range 2 {
					go func() {
						var err error
						cores[role], err = pair[role].AuthenticateCore(configs[role], fixtures[role].plan)
						results <- err
					}()
				}
				for range 2 {
					if err := waitRuntime(t, results); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				for role := range 2 {
					if err := pair[role].WaitCleanup(ctx); err != nil {
						t.Fatal(err)
					}
					if _, err := cores[role].Engine().ScopeFrontier(0, protocolv4.Direction(role)); err != nil {
						t.Fatal(err)
					}
					go func() { results <- cores[role].Runtime().Run(ctx) }()
				}
				client, server := cores[0].Admission(), cores[1].Admission()
				h, result, err := client.OpenLocal(ctx, BusinessStream, "example/raw", []byte("core"), &CarrierAssociation{shared: client.sharedIngress}, fixtures[0].streamReservation(t, cores[0]), streamTestDeadline(t, cores[0].Engine()))
				if err != nil || !result.Complete {
					t.Fatal(result, err)
				}
				peer := OpenHandle{server, h.scope}
				waitCoreOpen(t, server, peer, true)
				if _, err := server.Decide(ctx, peer, BusinessStream, "", fixtures[1].streamReservation(t, cores[1]), server.termination.writer); err != nil {
					t.Fatal(err)
				}
				waitCoreOpen(t, client, h, false)
				left, err := client.Flow(h)
				if err != nil {
					t.Fatal(err)
				}
				right, err := server.Flow(peer)
				if err != nil {
					t.Fatal(err)
				}
				for _, direction := range []struct {
					source, target *StreamFlow
					body           string
				}{{left, right, "client bytes"}, {right, left, "server bytes"}} {
					if n, err := direction.source.send.queueOwner.Write(ctx, []byte(direction.body)); err != nil || n != len(direction.body) {
						t.Fatal(n, err)
					}
					var dst [32]byte
					read, err := direction.target.receive.ReadInto(ctx, dst[:])
					if err != nil || string(dst[:read.Progress.Filled]) != direction.body {
						t.Fatal(read, err)
					}
				}
				for _, core := range cores {
					core.Close()
				}
				for range 2 {
					_ = waitRuntime(t, results)
				}
				for role, core := range cores {
					if err := core.WaitCleanup(ctx); err != nil {
						t.Fatal(role, err)
					}
					if err := core.Retire(); err != nil {
						t.Fatal(role, err)
					}
					if got := fixtures[role].root.Snapshot().Reservations; got != 1 {
						t.Fatal("core retained resources beyond the shared Environment", role, got)
					}
				}
			})
		}
	}
}

func TestInitialCoreCompletesReadyWithNoFreeReferenceSlots(t *testing.T) {
	for _, framing := range []string{"stream", "messages"} {
		t.Run(framing, func(t *testing.T) {
			var fixtures [2]initialCoreFixture
			pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, framing, 4, initialCorePrepareCarrier(t, &fixtures, framing == "messages"))
			var held []resourcev4.Reference
			defer func() {
				for _, ref := range held {
					ref.Release()
				}
			}()
			for role := range 2 {
				for {
					ref, err := fixtures[role].environment.Borrow()
					if err == resourcev4.ErrCapacity {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					held = append(held, ref)
				}
			}
			results := startInitialCorePair(pair, configs, &fixtures)
			for role := range 2 {
				if result := waitInitialCoreOutcome(t, results[role]); result.err != nil || result.core == nil {
					t.Fatal("assembly acquired a new reference after consuming the original plan", role, result.err)
				}
			}
			for _, ref := range held {
				ref.Release()
			}
			retireInitialCorePair(t, pair, &fixtures)
		})
	}
}

type shortCoreProvider struct{ bytes.Buffer }

func (p *shortCoreProvider) Write(b []byte) (int, error) {
	runtime.Gosched()
	return p.Buffer.Write(b[:min(1, len(b))])
}
func (p *shortCoreProvider) Close() error { return nil }

func TestSessionSharedCarrierKeepsWholeFramesAcrossShortWrites(t *testing.T) {
	provider := &shortCoreProvider{}
	charge, err := sessionStreamInputCharge(2)
	if err != nil {
		t.Fatal(err)
	}
	_, ref := testResourceReservation(t, charge, 1)
	carrier, err := newSessionStreamInput(provider, 2, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = carrier.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := carrier.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := carrier.Retire(); err != nil {
			t.Error(err)
		}
	})
	var wg sync.WaitGroup
	for _, b := range []byte{'a', 'b'} {
		wg.Go(func() {
			if n, err := carrier.Write(bytes.Repeat([]byte{b}, 128)); n != 128 || err != nil {
				t.Error(n, err)
			}
		})
	}
	wg.Wait()
	a, b := bytes.Repeat([]byte{'a'}, 128), bytes.Repeat([]byte{'b'}, 128)
	if got := provider.Bytes(); !bytes.Equal(got, append(bytes.Clone(a), b...)) && !bytes.Equal(got, append(bytes.Clone(b), a...)) {
		t.Fatal("encrypted envelopes interleaved")
	}
	if err := carrier.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := carrier.Write([]byte("late")); n != 0 || err != io.ErrClosedPipe {
		t.Fatal(n, err)
	}
}
