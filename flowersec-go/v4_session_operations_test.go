package flowersec

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func TestOperationPreparationKeepsFixedSessionAndOwner(t *testing.T) {
	ctx := context.Background()
	owner := &sessionv4.UnaryOperation{}
	digest := [32]byte{1}
	method := UnaryMethod{Contract: digest, WorkClass: WorkShort, Decode: func(context.Context, []byte) (any, error) { return nil, nil }}
	options := OperationOptions{DeadlineAtMS: 1<<53 + 123, ResponseLimitBytes: 64, AdmissionMode: 1, ExplicitAdmissionMode: true, RequireExecution: true}
	calls := 0
	session := &Session{prepareUnary: func(gotCtx context.Context, gotMethod sessionv4.UnaryMethodDefinition, input []byte, gotOptions rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error) {
		calls++
		if gotCtx != ctx || gotMethod.Contract != digest || string(input) != "request" || gotOptions.DeadlineAtMS != options.DeadlineAtMS || gotOptions.AdmissionMode != 1 || !gotOptions.RequireExecution {
			t.Error("changed fixed preparation")
		}
		return owner, nil
	}}
	handle, err := session.PrepareUnary(ctx, method, []byte("request"), options)
	if err != nil || handle.inner != owner || calls != 1 || handle.Status() != OperationPending {
		t.Fatal(handle, err, calls)
	}
	if _, err := handle.TakeEncodedResult(ctx); !errors.Is(err, ErrOperationNotStarted) {
		t.Fatal(err)
	}
	if _, err := handle.WaitStatus(ctx); !errors.Is(err, ErrOperationNotStarted) {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.PrepareUnary(ctx, method, nil, options); !errors.Is(err, ErrOperationClosed) {
		t.Fatal(err)
	}
	if handle.inner != owner {
		t.Fatal("session closure changed operation owner")
	}
}

func TestOperationProgressDoesNotInventRemoteExecution(t *testing.T) {
	if got := operationStatus(sessionv4.UnaryOperationSnapshot{Started: true}); got != OperationAccepted {
		t.Fatal(got)
	}
	if got := operationStatus(sessionv4.UnaryOperationSnapshot{Started: true, Result: sessionv4.UnaryResultStatus{Submission: rpcv4.PublicationProgress{Flushed: true}}}); got != OperationAccepted {
		t.Fatal(got)
	}
	result := operationResult(nil, nil, sessionv4.UnaryResultStatus{Complete: true}, context.Canceled)
	if result.Status != OperationCompleted || !errors.Is(result.Err, context.Canceled) {
		t.Fatal(result)
	}
	if status := (&UnaryRequest{}).ResponsePublication().State(); status.State != PublicationNotApplicable {
		t.Fatal(status)
	}
}

func TestServiceBindingValidatesImmutableDefault(t *testing.T) {
	method := UnaryMethod{Contract: [32]byte{1}, DefaultResponseLimitBytes: 65536, Decode: synchronousResultForAPI}
	session := &Session{prepareUnary: func(context.Context, sessionv4.UnaryMethodDefinition, []byte, rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error) {
		t.Fatal("binding encoded or prepared a request")
		return nil, nil
	}, bindUnaryService: func(got sessionv4.UnaryMethodDefinition) (*sessionv4.UnaryServiceClient, error) {
		if got.DefaultResponseLimitBytes != method.DefaultResponseLimitBytes {
			t.Fatal("binding replaced local default")
		}
		return nil, ErrResponseLimitUnsupported
	}}
	if client, err := session.BindService(method); err != ErrResponseLimitUnsupported || client != nil {
		t.Fatal(client, err)
	}
	if options := (OperationOptions{ExplicitResponseLimit: true}).internal(); !options.ExplicitResponseLimit || options.ResponseLimitBytes != 0 {
		t.Fatal("explicit zero became omitted", options)
	}
}

func synchronousResultForAPI(_ context.Context, value []byte) (any, error) { return value, nil }

func TestOperationManagementUsesCapturedOpaqueReference(t *testing.T) {
	calls := 0
	session := &Session{referenceManagement: func(ctx context.Context, ref protocolv4.OperationReference, cancel bool, timeout uint64) (rpcv4.ManagementResponse, error) {
		calls++
		if ctx == nil || !cancel || timeout != 30000 {
			t.Error("changed management intent")
		}
		return rpcv4.ManagementResponse{Status: "unknown", IsCancel: cancel}, nil
	}}
	result, err := session.RequestOperationCancel(context.Background(), OperationReference{}, 30000)
	if err != nil || result.Status != "unknown" || calls != 1 {
		t.Fatal(result, err)
	}
}
