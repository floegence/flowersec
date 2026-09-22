package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func TestGeneralCallerConcurrentResultsShareOriginalCompletionService(t *testing.T) {
	f, r, route := shortCallerFixture(t, 4)
	before := f.f.root.Snapshot()
	var header [512]byte
	n, h, err := f.codec.Encode(header[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: 3, DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var calls [2]*UnaryCall
	var decoded [2]string
	for j := range calls {
		calls[j], err = r.BeginUnary(ctx, route, h, header[:n], []byte("req"), ApplicationResident, func(input rpcv4.InputBorrow) error {
			p, _, err := input.Bytes()
			decoded[j] = string(p)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if r.localCall != nil {
		t.Fatal("general call borrowed short floor")
	}
	finishShortResponse(t, f, h, 1, []byte("first"))
	finishShortResponse(t, f, h, 2, []byte("second"))
	r.AdvanceCalls()
	for _, i := range r.generalCalls {
		if i == nil {
			continue
		}
		i.mu.Lock()
		task := i.task
		i.mu.Unlock()
		if task == nil {
			t.Fatal("result lost original Completion reservation")
		}
		if err := task.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	r.AdvanceCalls()
	for j, call := range calls {
		outcome, err := call.Wait(ctx)
		if err != nil || outcome.Error != nil || outcome.Reason != "" || outcome.SDKErrorCode != 0 {
			t.Fatal(j, outcome, err)
		}
	}
	if decoded != [2]string{"first", "second"} {
		t.Fatal("mixed original results", decoded)
	}
	if after := f.f.root.Snapshot(); after != before {
		t.Fatal("completed calls retained resources", before, after)
	}
}

func TestGeneralCallerNoCompletionCapacityLeavesRequestUnsubmitted(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	var header [512]byte
	n, h, err := f.codec.Encode(header[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: 3, DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	before := f.f.root.Snapshot()
	if call, err := r.BeginUnary(context.Background(), route, h, header[:n], []byte("req"), ApplicationResident, func(rpcv4.InputBorrow) error { t.Error("unadmitted decoder ran"); return nil }); call != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("call exceeded the original Completion cap", call, err)
	}
	if after := f.f.root.Snapshot(); after != before {
		t.Fatal("failed admission retained partial resources", before, after)
	}
	if progressed, err := f.publisher.Step(context.Background()); progressed || err != nil {
		t.Fatal("failed admission published bytes", progressed, err)
	}
	for _, call := range r.generalCalls {
		if call != nil {
			t.Fatal("failed admission retained call slot")
		}
	}
}
