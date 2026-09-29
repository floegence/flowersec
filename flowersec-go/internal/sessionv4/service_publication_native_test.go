package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestRestartPublicationUsesRuntimeOwnerAcrossEncryptedSessionRoles(t *testing.T) {
	body := restartFlushContract(t)
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := contract.Policy()
	contract.Release()
	if err != nil {
		t.Fatal(err)
	}
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 100000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) { return timev4.Tick{Incarnation: [16]byte{1}}, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1200, UpperMS: 1250}); err != nil {
		t.Fatal(err)
	}
	var fixtures [2]*executorFixture
	var environments [2]*Environment
	var maintenance [2]*MaintenanceOwner
	var publications [2]*ResponsePublication
	var entered [2]chan struct{}
	entered[0], entered[1] = make(chan struct{}, 1), make(chan struct{}, 1)
	cores, ctx := nativeTransportCorePairPrepared(t, protocolv4.DHProfileX25519, clock,
		func(role int, f *executorFixture, plan *SessionPlanConfig) {
			charge, err := MaintenanceOwnerCharge(2, 4096)
			if err != nil {
				t.Fatal(err)
			}
			maintenance[role], err = NewMaintenanceOwner(2, 4096, f.reserve(t, 1, charge))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(maintenance[role].Close)
			plan.MaintenanceOwner = maintenance[role]
		}, func(role int, f *executorFixture, plan *SessionPlan, config *RPCServicesConfig) {
			fixtures[role] = f
			config.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{body}}}
			config.Methods = []UnaryRegistration{{Method: 0, Namespace: policy.Namespace, Type: policy.Type, Handler: func(_ context.Context, request UnaryRequest, response *UnaryResponse) (uint32, error) {
				view := request.ResponsePublication()
				owner, err := request.MaintenanceOwner()
				if err != nil {
					return 0, err
				}
				if owner != maintenance[role] || view != request.ResponsePublication() || view.Progress().Terminal {
					return 0, errors.New("maintenance owner was not borrowed from original Runtime")
				}
				if err := view.TransferTo(owner); err != nil {
					return 0, err
				}
				if err := view.TransferTo(owner); !errors.Is(err, ErrPublicationAlreadyTransferred) {
					return 0, errors.New("duplicate observation transfer")
				}
				publications[role] = view
				entered[role] <- struct{}{}
				_, err = response.Write([]byte("maintenance accepted"))
				return 0, err
			}}}
			cfg := EnvironmentConfig{Services: true, ResultOwners: 16, Positions: 1, Clock: config.Clock, RuntimeBytes: 65536}
			charge, err := EnvironmentCharge(cfg)
			if err != nil {
				t.Fatal(err)
			}
			environments[role], err = NewEnvironment(cfg, f.reserve(t, 1, charge), f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				e := environments[role]
				e.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := e.WaitCleanup(cleanup); err != nil {
					t.Error(err)
				}
				if err := e.Retire(); err != nil {
					t.Error(err)
				}
			})
		}, "services")
	authorizeNativeServicePair(t, ctx, cores, fixtures, environments, policy, true)
	// This direct host fixture waits for the original channel supervisor's
	// publication, which normal Environment delivery already owns.
	for _, core := range cores {
		r := core.plan.rpc
		for {
			r.mu.Lock()
			ready := r.rpcPublisherLocked() != nil && r.dynamicChannels[0] != nil
			r.mu.Unlock()
			if ready {
				break
			}
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			runtime.Gosched()
		}
	}
	definition := ServiceDefinition{Namespace: policy.Namespace, Methods: []ServiceMethod{{Type: policy.Type, Shape: 0, Method: UnaryMethodDefinition{Contract: policy.Digest, DefaultResponseLimitBytes: 1024, Decode: func(_ context.Context, data []byte) (any, error) { return string(data), nil }}}}}
	for caller, core := range cores {
		service, err := core.plan.rpc.bindMethods(ctx, definition, UnaryServiceBindOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(service.Close)
		operation, err := service.PrepareMethod(ctx, policy.Type, []byte("restart"), rpcv4.UnaryPreparation{DefaultLifetimeMS: 1000})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(operation.Close)
		if err := operation.Start(ctx).Error; err != nil {
			t.Fatal(err)
		}
		if caller == 0 {
			result, status, err := operation.TakeResult(ctx)
			if err != nil || !status.Delivered || result != "maintenance accepted" {
				t.Fatal(result, status, err)
			}
		} else {
			result, status, err := operation.TakeEncodedResult(ctx)
			if err != nil || !status.Delivered || string(result) != "maintenance accepted" {
				t.Fatal(string(result), status, err)
			}
		}
		provider := 1 - caller
		select {
		case <-entered[provider]:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		view := publications[provider]
		progress, err := view.Wait(ctx)
		if err != nil || !progress.Terminal || !progress.Flushed {
			t.Fatal("original response publication", progress, err)
		}
		operation.Close()
		service.Close()
		if err := operation.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
		maintenance[provider].Close()
		if err := maintenance[provider].WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
		if !view.Progress().Flushed {
			t.Fatal("maintenance close rewrote publication")
		}
	}
	for _, core := range cores {
		if _, err := core.ProbeLiveness(ctx, 1000); err != nil {
			t.Fatal("publication closed shared transport", err)
		}
	}
}
