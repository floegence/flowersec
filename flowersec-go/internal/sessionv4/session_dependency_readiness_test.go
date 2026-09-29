package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestInvocationMissingShapeFailsBeforeEncoding(t *testing.T) {
	for _, shape := range []uint8{0, 1, 2} {
		t.Run([]string{"unary", "stream", "notify"}[shape], func(t *testing.T) {
			f, r, _, definition := serviceShapesFixture(t)
			encoded := 0
			definition.Methods[shape].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(context.Context, []byte, []byte) ([]byte, error) {
				encoded++
				return []byte("encoded"), nil
			}}
			client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			r.mu.Lock()
			r.channel = nil
			r.mu.Unlock()
			runSynchronousParent(t, f, ApplicationShort, func(ctx context.Context) {
				before := f.f.root.Snapshot()
				options := rpcv4.UnaryPreparation{DeadlineAtMS: 2000}
				var failure error
				switch shape {
				case 0:
					op, err := client.PrepareMethod(ctx, 1, nil, options)
					failure = err
					if op != nil {
						op.Close()
						t.Fatal("missing path manufactured a prepared handle")
					}
				case 1:
					op, err := client.PrepareStreamingMethod(ctx, 2, nil, options)
					failure = err
					if op != nil {
						op.Close()
						t.Fatal("empty pool manufactured a prepared handle")
					}
				case 2:
					op, err := client.PrepareNotifyMethod(ctx, 3, nil, options)
					failure = err
					if op != nil {
						op.Close()
						t.Fatal("missing notify path manufactured a prepared handle")
					}
				}
				if !errors.Is(failure, cryptov4.ErrNotReady) || encoded != 0 || f.f.root.Snapshot() != before {
					t.Fatal("missing dependency encoded or retained resources", failure, encoded, before, f.f.root.Snapshot())
				}
				if len(f.sink.wire) != 0 || r.network.Snapshot().OutgoingGeneral != 0 {
					t.Fatal("readiness started hidden network work")
				}
			})
		})
	}
}

func TestInvocationClosedPublisherFailsBeforeEncoding(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	f.publisher.Close()
	runSynchronousParent(t, f, ApplicationShort, func(ctx context.Context) {
		encoded := false
		op, err := r.PrepareEncodedUnaryResult(ctx, route, nil, synchronousOptions(), ApplicationShort, SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(context.Context, []byte, []byte) ([]byte, error) {
			encoded = true
			return nil, nil
		}}, synchronousResult)
		if op != nil || !errors.Is(err, cryptov4.ErrNotReady) || encoded {
			t.Fatal("closed original publisher entered encoder", err, encoded)
		}
	})
}

func TestNotifyInvocationUsesActualAcceptedChannelDuringRekey(t *testing.T) {
	ctx, services, fixtures, endpoints, channels, _ := notificationRuntimeFixture(t)
	policy := authorizeNotificationRuntime(t, services[0], fixtures[0])
	authorizeNotificationRuntime(t, services[1], fixtures[1])
	r, f := services[0], fixtures[0]
	encoded := 0
	method := UnaryMethodDefinition{Contract: policy.Digest, Codec: SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(context.Context, []byte, []byte) ([]byte, error) {
		encoded++
		return []byte("notice"), nil
	}}}
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes(), resourcev4.Items: 1})
	permit, err := f.executor.TryAcquire(ApplicationShort, f.reserve(t, 1, f.executor.TaskCharge()), backing)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()
	var current context.Context
	var exit func()
	if err = permit.runInline(func() {
		current, exit, err = enterApplicationContext(ctx, f.executor, ordinaryApplicationLane, ApplicationShort, backing, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer exit()
		op, failure := r.prepareNotifyMethod(current, method, nil, rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000})
		if op != nil || !errors.Is(failure, cryptov4.ErrNotReady) || encoded != 0 {
			t.Error("ordinary RPC path substituted for NOTIFY", failure, encoded)
		}
	}); err != nil {
		t.Fatal(err)
	}
	// Establishment is explicit setup outside an application invocation.
	notify, err := r.OpenNotifyChannel(ctx, streamTestDeadline(t, endpoints[0].engine))
	if err != nil {
		t.Fatal(err)
	}
	var frontiers [32]protocolv4.RecordHeader
	freeze, _, err := endpoints[0].engine.FreezeApplication(frontiers[:])
	if err != nil {
		t.Fatal(err)
	}
	defer freeze.Cancel()
	if !notify.dependencyReady() || !channels[0].dependencyReady() {
		t.Fatal("legal record freeze removed accepted structural readiness")
	}
	// The first inline task used its permit. A second real ordinary slot runs
	// the successful encoding while the original record ticket gate is frozen.
	second, err := f.executor.TryAcquire(ApplicationShort, f.reserve(t, 1, f.executor.TaskCharge()), backing)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.runInline(func() {
		current, exit, err := enterApplicationContext(ctx, f.executor, ordinaryApplicationLane, ApplicationShort, backing, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer exit()
		op, err := r.prepareNotifyMethod(current, method, nil, rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000})
		if err != nil || op == nil || encoded != 1 {
			t.Error("accepted notify path rejected rekey preparation", err, encoded)
			return
		}
		op.Close()
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPreacceptedServiceCapacityIncludesPendingAndClosing(t *testing.T) {
	p := &SessionCorePlan{}
	for index := range 2 {
		e := &preacceptedStream{closed: index == 1}
		e.namespaceBytes = copy(e.namespace[:], "files")
		p.preaccepted[index] = e
	}
	if err := p.preacceptedServiceCapacityLocked("files"); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("different methods or closing entries enlarged service pool", err)
	}
	if err := p.preacceptedServiceCapacityLocked("terminals"); err != nil {
		t.Fatal("another namespace inherited this service's limit", err)
	}
	p.preaccepted[1] = nil
	if err := p.preacceptedServiceCapacityLocked("files"); err != nil {
		t.Fatal("actual cleanup did not return original service position", err)
	}
}

func TestPreacceptedIdleWindowCannotRenewOrChangeBusinessDeadline(t *testing.T) {
	var tick uint64
	clock := newTestRekeyClock(t, timev4.Rate{Denominator: 1, QuantizationMS: 1}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: tick, Incarnation: [16]byte{1}}, nil
	})
	deadline, err := timev4.NewDeadline(clock, 200000)
	if err != nil {
		t.Fatal(err)
	}
	idle, err := timev4.NewWindow(clock, preacceptedIdleMS)
	if err != nil {
		t.Fatal(err)
	}
	for _, tickValue := range []uint64{1, 10000, 20000, 29998} {
		tick = tickValue
		if err := idle.Check(); err != nil {
			t.Fatal(err)
		}
	}
	tick = 30000
	if !errors.Is(idle.Check(), timev4.ErrExpired) || deadline.Cap() != 200000 {
		t.Fatal("idle checks renewed the window or changed business cap")
	}
}
