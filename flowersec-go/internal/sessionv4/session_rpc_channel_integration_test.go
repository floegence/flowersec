package sessionv4

import (
	"context"
	"crypto/sha256"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func rpcChannelRuntimeFixture(t *testing.T) (context.Context, [2]*RPCServices, [2]*executorFixture, [2]*bootstrapEndpoint, [2]*RPCChannel, [2][16]byte) {
	return rpcChannelRuntimeFixtureConfigured(t, nil)
}

func rpcChannelRuntimeFixtureConfigured(t *testing.T, configure func(int, *executorFixture, *SessionPlan, *RPCServicesConfig)) (context.Context, [2]*RPCServices, [2]*executorFixture, [2]*bootstrapEndpoint, [2]*RPCChannel, [2][16]byte) {
	return rpcChannelRuntimeProfile(t, "services", configure)
}
func rpcChannelRuntimeProfile(t *testing.T, application string, configure func(int, *executorFixture, *SessionPlan, *RPCServicesConfig)) (context.Context, [2]*RPCServices, [2]*executorFixture, [2]*bootstrapEndpoint, [2]*RPCChannel, [2][16]byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close() })
	t.Cleanup(func() { _ = right.Close() })
	pipes := [2]net.Conn{left, right}
	var services [2]*RPCServices
	var fixtures [2]*executorFixture
	var inputs [2]*sessionStreamInput
	var endpoints [2]*bootstrapEndpoint
	var done [2][6]chan error
	var dispatchers [2]*sessionStreamDispatcher
	client, server := newBootstrapPairSetupCapacity(t, protocolv4.DHProfileX25519, application, true, 1<<20, 12, func(role int, e *bootstrapEndpoint) *Bootstrap {
		endpoints[role] = e
		f, p, c := rpcServicesPlanFixture(t)
		fixtures[role] = f
		c.Session = e.engine.SessionParameters().Contract
		c.Clock = e.engine.Clock()
		c.Routes.Clock = c.Clock
		if configure != nil {
			configure(role, f, p, &c)
		}
		r, err := p.InstallRPCServices(c)
		if err != nil {
			t.Fatal(err)
		}
		services[role] = r
		charge, err := sessionStreamInputCharge(6)
		if err != nil {
			t.Fatal(err)
		}
		inputs[role], err = newSessionStreamInput(pipes[role], 6, f.reserve(t, 1, charge))
		if err != nil {
			t.Fatal(err)
		}
		e.maintenance, err = NewRecordWriter(e.engine, 0, inputs[role])
		if err != nil {
			t.Fatal(err)
		}
		poolSlots := uint32(10)
		workers := [3]uint32{1, 1}
		if application == "execution" {
			poolSlots++
			workers[2] = 1
		}
		charge, err = ReceivePoolCharge(c.Bootstrap.ReceivePoolBytes, poolSlots)
		if err != nil {
			t.Fatal(err)
		}
		e.pool, err = NewReceivePool(e.engine.SessionParameters().Contract.Limits().MaxCredit, c.Bootstrap.ReceivePoolBytes, poolSlots, f.reserve(t, 1, charge))
		if err != nil {
			t.Fatal(err)
		}
		charge, err = SendServiceCharge(12, workers)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = NewSendService(e.admission, workers, f.reserve(t, 1, charge)); err != nil {
			t.Fatal(err)
		}
		charge, err = StreamTerminationServiceCharge(12)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = NewStreamTerminationService(e.admission, e.maintenance, StreamTerminationPolicy{NormalMS: 1000, QuarantineMS: 1000, QuarantineDirections: 8}, f.reserve(t, 1, charge)); err != nil {
			t.Fatal(err)
		}
		retirement, err := NewRetirement(e.admission, e.maintenance)
		if err != nil {
			t.Fatal(err)
		}
		charge, err = RetirementServiceCharge()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = NewRetirementService(retirement, 1000, f.reserve(t, 1, charge)); err != nil {
			t.Fatal(err)
		}
		decode := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
		charge, err = SharedIngressCharge(65536, 128, decode)
		if err != nil {
			t.Fatal(err)
		}
		g, err := NewSharedIngress(e.admission, &CarrierAssociation{}, SharedDiscardPolicy{16, 65536, 10000}, 128, decode, f.reserve(t, 1, charge))
		if err != nil {
			t.Fatal(err)
		}
		before := f.root.Snapshot()
		bootstrap, err := r.PrepareBootstrap(g, e.pool, inputs[role])
		if err != nil {
			t.Fatal(err)
		}
		if after := f.root.Snapshot(); after.Charged != before.Charged || after.Reservations != before.Reservations {
			t.Fatal("bootstrap allocated omitted resources", before, after)
		}
		return bootstrap
	})

	// This test exercises the real bootstrap/channel pipeline. The full public
	// admission/authority factory is not established by this component test.
	t.Cleanup(func() {
		cancel()
		for role, e := range endpoints {
			if dispatchers[role] != nil {
				dispatchers[role].Close()
			}
			services[role].Close()
			e.admission.Close()
			inputs[role].Close()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for role, e := range endpoints {
			for _, exit := range done[role] {
				if exit != nil {
					select {
					case <-exit:
					case <-cleanup.Done():
						t.Error("service tail", cleanup.Err())
					}
				}
			}
			if d := dispatchers[role]; d != nil {
				if err := d.WaitCleanup(cleanup); err != nil {
					t.Error(err)
				}
				if err := d.Retire(); err != nil {
					t.Error(err)
				}
			}
			if err := services[role].waitChannel(cleanup); err != nil {
				t.Error(err)
			}
			if err := e.admission.sendService.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if err := e.admission.termination.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if err := e.admission.retirementService.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if err := e.admission.cleanupClosed(cleanup); err != nil {
				t.Error(err)
			}
			if err := e.admission.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if err := e.admission.Retire(); err != nil {
				t.Error(err)
			}
			if err := inputs[role].WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if err := inputs[role].Retire(); err != nil {
				t.Error(err)
			}
		}
	})
	client.complete(t, server)
	server.complete(t, client)
	for role, e := range endpoints {
		done[role][0] = make(chan error, 1)
		go func() {
			for {
				deadline, err := timev4.NewAge(e.engine.Clock(), 10000, e.engine.SessionParameters().SessionNotAfterMS)
				if err == nil {
					err = e.admission.sharedIngress.ReadDispatch(ctx, inputs[role], deadline)
				}
				if err != nil {
					e.admission.closeWithCause(err)
					done[role][0] <- err
					return
				}
			}
		}()
	}
	var channels [2]*RPCChannel
	var identities [2][16]byte
	for role, e := range endpoints {
		before := fixtures[role].root.Snapshot()
		r := services[role]
		var seed [32]byte
		copy(seed[:16], r.owner.Instance[:])
		copy(seed[16:], r.owner.Backing[:])
		digest := sha256.Sum256(seed[:])
		copy(identities[role][:], digest[:16])
		done[role][1], done[role][2], done[role][3] = make(chan error, 1), make(chan error, 1), make(chan error, 1)
		go func() { done[role][1] <- e.admission.sendService.Run(ctx) }()
		go func() { done[role][2] <- e.admission.termination.Run(ctx) }()
		done[role][5] = make(chan error, 1)
		go func() { done[role][5] <- e.admission.retirementService.Run(ctx) }()
		go func() { done[role][3] <- r.run(ctx) }()
		for {
			r.mu.Lock()
			channel := r.channel
			registered := r.dynamicChannels[0] != nil
			r.mu.Unlock()
			if channel != nil && registered {
				channels[role] = channel
				break
			}
			if ctx.Err() != nil {
				t.Fatal("original initializer did not materialize channel", ctx.Err())
			}
			runtime.Gosched()
		}
		if after := fixtures[role].root.Snapshot(); after.Charged != before.Charged || after.Reservations != before.Reservations {
			t.Fatal("channel stole dynamic capacity", before, after)
		}
	}
	for role, e := range endpoints {
		cfg := SessionStreamHandlerConfig{internal: true, RuntimeBytes: 4096}
		charge, err := sessionStreamDispatcherCharge(cfg)
		if err != nil {
			t.Fatal(err)
		}
		core := &SessionCore{plan: &SessionCorePlan{admission: e.admission, writer: e.maintenance, rpc: services[role]}}
		d, err := newSessionStreamDispatcher(core, cfg, fixtures[role].reserve(t, 1, charge))
		if err != nil {
			t.Fatal(err)
		}
		dispatchers[role] = d
		done[role][4] = make(chan error, 1)
		go func() { done[role][4] <- d.Run(ctx) }()
	}
	return ctx, services, fixtures, endpoints, channels, identities
}

func TestRPCServicesOriginalBootstrapChannelDuplexAndContinuousCredit(t *testing.T) {
	ctx, services, fixtures, endpoints, channels, identities := rpcChannelRuntimeFixture(t)
	for role := range 2 {
		assertRPCChannelRefusal(t, ctx, services[role], fixtures[role], channels[role], identities[role])
		if err := endpoints[role].engine.ApplicationReady(); err != nil {
			t.Fatal("local rejection closed Session", err)
		}
		if usage := endpoints[role].admission.Usage(); usage.Active != 1 || usage.Pending != 0 {
			t.Fatal("fixed channel created OPEN outcome", usage)
		}
	}
}

func assertRPCChannelRefusal(t *testing.T, ctx context.Context, r *RPCServices, f *executorFixture, channel *RPCChannel, identity [16]byte) {
	t.Helper()
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 40000)
	var encoded [512]byte
	now, err := r.clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	length, header, err := codec.Encode(encoded[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: 123, PayloadBytes: uint32(len(payload)), DeadlineAtMS: now.UpperMS + 10000, ServiceContractDigest: [32]byte{5}, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := r.network.ReserveOutgoing(header, rpcv4.Association{Channel: identity})
	if err != nil {
		t.Fatal(err)
	}
	charge, err := rpcv4.CompletionCharge(1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := r.network.NewCompletion(ticket, 1024, f.reserveOwner(t, 1, charge, true), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer completion.Close()
	charge, err = rpcv4.MessageSourceCharge(uint32(len(payload)), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = channel.Publisher().QueueRequest(ticket, encoded[:length], payload, f.reserve(t, 1, charge), 4096); err != nil {
		t.Fatal(err)
	}
	select {
	case <-completion.Done():
	case <-ctx.Done():
		t.Fatal("fixed refusal blocked behind input credit", ctx.Err())
	}
	if progress := completion.Progress(); !progress.Complete || progress.SDKErrorCode == 0 || progress.Reason != "" {
		t.Fatal(progress)
	}
}
