package sessionv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

type workloadNotifySink struct {
	accepted, completed atomic.Uint64
	wake                chan struct{}
}

func (s *workloadNotifySink) TryAcceptNotify(context.Context, []byte) (uint64, error) {
	return s.accepted.Add(1), nil
}
func (s *workloadNotifySink) Published(id uint64) (bool, error) { return s.NotifyTailReleased(id), nil }
func (s *workloadNotifySink) NotifyTailReleased(id uint64) bool { return s.completed.Load() >= id }
func (s *workloadNotifySink) Wake() <-chan struct{}             { return s.wake }
func (s *workloadNotifySink) flush()                            { s.completed.Store(s.accepted.Load()) }

// Only the host/carrier attachments are fixture-supplied. Method authority,
// route capture, codec admission, publisher, workload and cleanup are real.
func notifyWorkloadFixture(t *testing.T, encoded bool) (*notificationFixture, *RPCServices, *Environment, ServiceDefinition) {
	t.Helper()
	f := newNotificationFixture(t)
	config := EnvironmentConfig{Services: true, ResultOwners: 4, Positions: 1, Clock: f.trust.clock, RuntimeBytes: 65536}
	charge, err := EnvironmentCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvironment(config, f.f.reserve(t, 1, charge), f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}))
	if err != nil {
		t.Fatal(err)
	}
	r := &RPCServices{root: f.f.root, owner: f.d.owner, routes: f.routes, notifications: f.d, plan: f.plan, clock: f.trust.clock, runtimeBytes: 4096,
		operations: make([]*UnaryOperation, 32), generalCalls: make([]*unaryInvocation, 32), workloadSlots: make([]*unaryWorkloadSlot, 32),
		notifyPublisherConfig: rpcv4.NotifyPublisherConfig{Pending: 2, RuntimeBytes: 4096}}
	nc := rpcv4.NetworkConfig{Session: testSessionContract(t, protocolv4.DHProfileX25519, "services", 4096, 4, 0, 5000).Contract, Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}}, RuntimeBytes: 4096}
	charge, err = rpcv4.NetworkCharge(nc)
	if err != nil {
		t.Fatal(err)
	}
	r.network, err = rpcv4.NewNetwork(nc, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.network.Close)
	host := newEnvironmentSession(e, 0, context.Background())
	host.core, host.delivered = &SessionCore{plan: &SessionCorePlan{rpc: r}}, true
	f.plan.mu.Lock()
	f.plan.host = host
	f.plan.mu.Unlock()
	method := ServiceMethod{Type: f.policy.Type, Shape: 2, Method: UnaryMethodDefinition{Contract: f.policy.Digest}}
	if encoded {
		method.Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 16, ScratchBytes: 16, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) { return input, nil }}
	}
	t.Cleanup(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		r.AdvanceCalls()
		e.Close()
		if err := e.WaitCleanup(resultTestContext(t)); err != nil {
			t.Error(err)
		}
		if err := e.Retire(); err != nil {
			t.Error(err)
		}
	})
	return f, r, e, ServiceDefinition{Namespace: f.policy.Namespace, Methods: []ServiceMethod{method}}
}

func attachNotifyWorkloadPublisher(t *testing.T, f *notificationFixture, r *RPCServices, position int) (*rpcv4.NotifyPublisher, *workloadNotifySink) {
	t.Helper()
	sink := &workloadNotifySink{wake: make(chan struct{}, 1)}
	charge, err := rpcv4.NotifyPublisherCharge(r.notifyPublisherConfig)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := rpcv4.NewNotifyPublisher(sink, r.notifyPublisherConfig, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	err = r.protectNotifyChannelLocked(publisher, position)
	if err == nil {
		r.notifyChannels[position] = &notifyChannelOpening{channel: &NotifyChannel{publisher: publisher}}
	}
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sink.flush()
		publisher.Close()
		if err := publisher.Retire(); err != nil {
			t.Error(err)
		}
		r.AdvanceCalls()
		r.mu.Lock()
		r.notifyChannels[position] = nil
		r.mu.Unlock()
	})
	return publisher, sink
}

func bindNotifyWorkload(t *testing.T, r *RPCServices, e *Environment, definition ServiceDefinition) (*UnaryServiceClient, *unaryWorkload) {
	t.Helper()
	before, network := e.OperationsSnapshot(), r.network.Snapshot()
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{Workloads: []ServiceMethodWorkload{{Type: definition.Methods[0].Type, Calls: 1, RequestBytes: 8}}})
	if err != nil {
		t.Fatal(err)
	}
	w := client.methods[0].definition.Method.workload
	if w.shape != 2 || w.slots[0].completion != nil || w.slots[0].network != (rpcv4.OutgoingProtection{}) || w.slots[0].authority != nil || before.ProtectedResults != e.OperationsSnapshot().ProtectedResults || network != r.network.Snapshot() {
		t.Fatal("notification consumed a unary result or network responsibility")
	}
	t.Cleanup(func() {
		closeWorkloadClient(t, client, r, e)
		waitWorkload(t, r, e, func() bool { return w.cleaned })
	})
	return client, w
}

func TestNotifyWorkloadUsesOriginalCapacityAtFullRoot(t *testing.T) {
	for _, encoded := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "codec"}[encoded], func(t *testing.T) {
			f, r, e, definition := notifyWorkloadFixture(t, encoded)
			p, sink := attachNotifyWorkloadPublisher(t, f, r, 0)
			client, w := bindNotifyWorkload(t, r, e, definition)
			saturateWorkloadRoot(t, &serviceDispatchFixture{f: f.f})
			before := f.f.root.Snapshot()
			for range 2 {
				op, err := client.PrepareNotifyMethod(context.Background(), f.policy.Type, []byte("notify"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
				if err != nil {
					t.Fatal("protected preparation", err)
				}
				t.Cleanup(op.Close)
				if op.owner.workload != &w.slots[0] {
					t.Fatal("lost original workload")
				}
				if start := op.Start(context.Background()); start.Error != nil {
					t.Fatal("protected Start", start.Error)
				}
				if start := op.Start(context.Background()); start.Error != nil {
					t.Fatal("repeated Start", start.Error)
				}
				if _, err := p.Step(context.Background()); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				done := make(chan error, 4)
				for range 4 {
					go func() { _, err := op.WaitSubmission(ctx); done <- err }()
				}
				until := resultTestContext(t)
				for {
					op.owner.notify.mu.Lock()
					count := op.owner.notify.waiters
					op.owner.notify.mu.Unlock()
					if count == 4 {
						break
					}
					select {
					case err := <-done:
						t.Fatal("preadmitted wait failed", err)
					case <-until.Done():
						t.Fatal("waiters did not enter")
					case <-time.After(time.Millisecond):
					}
				}
				if _, err := op.WaitSubmission(ctx); !errors.Is(err, rpcv4.ErrCapacity) {
					t.Fatal("unbounded waiters", err)
				}
				if _, err := client.PrepareNotifyMethod(context.Background(), f.policy.Type, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000}); !errors.Is(err, resourcev4.ErrCapacity) {
					t.Fatal("duplicated declared target", err)
				}
				sink.flush()
				if _, err := p.Step(context.Background()); err != nil {
					t.Fatal(err)
				}
				for range 4 {
					if err := <-done; err != nil {
						t.Fatal(err)
					}
				}
				cancel()
				op.Close()
				r.AdvanceCalls()
				if !w.slots[0].used {
					t.Fatal("provider tail refunded early")
				}
				sink.flush()
				if _, err := p.Step(context.Background()); err != nil {
					t.Fatal(err)
				}
				waitWorkload(t, r, e, func() bool { return !w.slots[0].used })
				if f.f.root.Snapshot() != before {
					t.Fatal("original reusable backing changed")
				}
			}
		})
	}
}

func TestNotifyWorkloadCandidateRejectsInsufficientQueueAtomically(t *testing.T) {
	f, r, e, definition := notifyWorkloadFixture(t, false)
	attachNotifyWorkloadPublisher(t, f, r, 0)
	attachNotifyWorkloadPublisher(t, f, r, 1)
	client, w := bindNotifyWorkload(t, r, e, definition)
	before := f.f.root.Snapshot()
	_, err := r.qualifyUnaryWorkload(definition.Methods[0], ServiceMethodWorkload{Type: f.policy.Type, Calls: 2, RequestBytes: 8}, nil)
	if !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("oversubscribed queues", err)
	}
	if before != f.f.root.Snapshot() || client.methods[0].definition.Method.workload != w {
		t.Fatal("failed candidate damaged original target")
	}
}

func TestNotifyWorkloadRebuildKeepsOriginalStatusTail(t *testing.T) {
	f, r, e, definition := notifyWorkloadFixture(t, false)
	client, w := bindNotifyWorkload(t, r, e, definition)
	p, sink := attachNotifyWorkloadPublisher(t, f, r, 0)
	op, err := client.PrepareNotifyMethod(context.Background(), f.policy.Type, []byte("notice"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if start := op.Start(context.Background()); start.Error != nil {
		t.Fatal(start.Error)
	}
	if _, err := p.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if err := p.Retire(); !errors.Is(err, rpcv4.ErrCapacity) {
		t.Fatal("channel cleanup ignored its tail", err)
	}
	sink.flush()
	if err := p.Retire(); err != nil {
		t.Fatal(err)
	}
	r.AdvanceCalls()
	if !w.slots[0].used {
		t.Fatal("retained status refunded target")
	}
	next, nextSink := attachNotifyWorkloadPublisher(t, f, r, 0)
	op.Close()
	waitWorkload(t, r, e, func() bool { return !w.slots[0].used })
	second, err := client.PrepareNotifyMethod(context.Background(), f.policy.Type, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Close)
	if start := second.Start(context.Background()); start.Error != nil {
		t.Fatal(start.Error)
	}
	for range 3 {
		nextSink.flush()
		if _, err := next.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !second.SubmissionStatus().Flushed || sink.accepted.Load() != 1 {
		t.Fatal("channel rebuild replayed or lost a message")
	}
	second.Close()
	waitWorkload(t, r, e, func() bool { return !w.slots[0].used })
}

func TestSessionNotifyWorkloadOriginalAdmission(t *testing.T) {
	for _, controller := range []bool{false, true} {
		t.Run(map[bool]string{false: "consumer", true: "controller"}[controller], func(t *testing.T) {
			f, e := sessionWorkloadFixture(t)
			wire := initialFixture(t, "service_notify_observation")
			codec, err := protocolv4.NewServiceContractCodec(256)
			if err != nil {
				t.Fatal(err)
			}
			contract, err := codec.Decode(wire)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := contract.Policy()
			contract.Release()
			if err != nil {
				t.Fatal(err)
			}
			c := f.config.RPC
			c.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{wire}}}
			c.NotificationMethods = []NotificationMethod{{Method: 0}}
			c.Workloads = []SessionMethodWorkload{{Namespace: policy.Namespace, Method: ServiceMethod{Type: policy.Type, Shape: 2, Method: UnaryMethodDefinition{Contract: policy.Digest}}, Workload: ServiceMethodWorkload{Type: policy.Type, Calls: 2, RequestBytes: 8}}}
			want, count, err := SessionAdmissionRequirements(f.config)
			if err != nil {
				t.Fatal(err)
			}
			before := f.root.Snapshot()
			var original *unaryWorkload
			if controller {
				h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
				if err != nil {
					t.Fatal(err)
				}
				defer h.close()
				original = h.workloads
				f.config.headroom = h
			}
			hostWorkloadPlan(t, f, e)
			a := f.reserve(t, context.Background())
			expected, _ := before.Charged.Add(want)
			after := f.root.Snapshot()
			if after.Charged != expected || after.Reservations != before.Reservations+count {
				t.Fatal("notification requirements differ from real admission", expected, after.Charged)
			}
			w := a.application.rpc.initialWorkloads[0]
			if w == nil || w.shape != 2 || original != nil && w != original || len(w.slots) != 2 {
				t.Fatal("lost original notification target")
			}
			for i := range w.slots {
				slot := &w.slots[i]
				if slot.completion != nil || slot.authority != nil || slot.authorityBacking != (resourcev4.Reference{}) || slot.network != (rpcv4.OutgoingProtection{}) {
					t.Fatal("notification claimed unary responsibilities")
				}
			}
			if e.OperationsSnapshot().ProtectedResults != 1 || a.claimed || a.committed || a.activated || f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
				t.Fatal("target crossed original admission boundaries")
			}
		})
	}
}
