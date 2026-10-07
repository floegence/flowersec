package flowersec

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func TestContractQueryPreservesOriginalSessionOwner(t *testing.T) {
	ctx := context.Background()
	target := ServiceContractTarget{Namespace: "example/files", Type: 1, HasWanted: true, Wanted: [32]byte{1}, MaxOfferWindowMS: 1000}
	result := &sessionv4.ContractQuerySnapshots{}
	calls := 0
	session := &Session{queryServiceContracts: func(got context.Context, targets []sessionv4.ServiceContractTarget) (*sessionv4.ContractQuerySnapshots, error) {
		calls++
		if got != ctx || len(targets) != 1 || targets[0] != target {
			t.Fatal("query adapter changed original scope")
		}
		return result, nil
	}}
	got, err := session.QueryServiceContracts(ctx, []ServiceContractTarget{target})
	if err != nil || got != result || calls != 1 {
		t.Fatal(got, calls, err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.QueryServiceContracts(ctx, []ServiceContractTarget{target}); !errors.Is(err, ErrOperationClosed) || calls != 1 {
		t.Fatal("closed facade forwarded query", calls, err)
	}
	if _, err := (&Session{}).QueryServiceContracts(ctx, []ServiceContractTarget{target}); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatal("unavailable facade queried", err)
	}
}
