package transporttest

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier"
)

func TestOpenAdaptiveEndpointRejectsInvalidCandidates(t *testing.T) {
	tests := []struct {
		name       string
		candidates []AdaptiveCandidate
	}{
		{name: "count", candidates: []AdaptiveCandidate{{ID: "wss", Kind: carrier.KindWebSocket}}},
		{name: "empty ID", candidates: []AdaptiveCandidate{{Kind: carrier.KindWebSocket}, {ID: "quic", Kind: carrier.KindRawQUIC}}},
		{name: "duplicate ID", candidates: []AdaptiveCandidate{{ID: "same", Kind: carrier.KindWebSocket}, {ID: "same", Kind: carrier.KindRawQUIC}}},
		{name: "duplicate carrier", candidates: []AdaptiveCandidate{{ID: "first", Kind: carrier.KindWebSocket}, {ID: "second", Kind: carrier.KindWebSocket}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if endpoint, err := OpenAdaptiveEndpointAt(context.Background(), "127.0.0.1", test.candidates); err == nil {
				_ = endpoint.Close()
				t.Fatal("accepted invalid adaptive candidates")
			}
		})
	}
}

func TestAdaptiveEndpointRacesProductionCarriers(t *testing.T) {
	requireTransportIntegration(t)
	for _, test := range []struct {
		name       string
		candidates []AdaptiveCandidate
	}{
		{name: "native", candidates: []AdaptiveCandidate{{ID: "runtime-wss", Kind: carrier.KindWebSocket}, {ID: "runtime-raw-quic", Kind: carrier.KindRawQUIC}}},
		{name: "web", candidates: []AdaptiveCandidate{{ID: "runtime-wss", Kind: carrier.KindWebSocket}, {ID: "runtime-webtransport", Kind: carrier.KindWebTransport}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			endpoint, err := OpenAdaptiveEndpointAt(ctx, "127.0.0.1", test.candidates)
			if err != nil {
				t.Fatal(err)
			}
			pair, started, winner, commits, writes, err := endpoint.Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(started) != 2 || !slices.Contains(started, test.candidates[0].ID) || !slices.Contains(started, test.candidates[1].ID) {
				t.Fatalf("started candidates = %v", started)
			}
			if !slices.Contains(started, winner) || commits != 1 || writes != 1 {
				t.Fatalf("winner = %q, commits = %d, writes = %d", winner, commits, writes)
			}
			if err := pair.Close(); err != nil {
				t.Fatal(err)
			}
			if err := endpoint.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRunAdaptiveColdRecordsEveryRealSelection(t *testing.T) {
	requireTransportIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	endpoint, err := OpenAdaptiveEndpointAt(ctx, "127.0.0.1", []AdaptiveCandidate{
		{ID: "runtime-wss", Kind: carrier.KindWebSocket},
		{ID: "runtime-raw-quic", Kind: carrier.KindRawQUIC},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	results, err := RunAdaptiveCold(ctx, endpoint, ColdPlan{
		Operations: 2, MaxInflight: 2, StartRatePerSecond: 100,
		OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("result count = %d, want 2", len(results))
	}
	for index, result := range results {
		if result.Ordinal != index+1 || len(result.StartedCandidates) != 2 || result.WinnerCandidate == "" ||
			result.CommitCount != 1 || result.CredentialWriteCount != 1 || result.Duration <= 0 || result.CleanupDuration <= 0 {
			t.Fatalf("result %d = %+v", index+1, result)
		}
	}
}
