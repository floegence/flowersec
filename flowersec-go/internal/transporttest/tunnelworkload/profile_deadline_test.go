package tunnelworkload

import (
	"bytes"
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest"
	"testing"
	"time"
)

// This exercises original issuance, registration, native HOP/Noise/READY and
// application service admission with a profile above the former 30s cap. It
// does not simulate elapsed time or qualify a deliberately slow network.
func TestCurrentTunnel53SecondProfileAdmitsOriginalPoolAndAllowance(t *testing.T) {
	for _, topology := range Topologies() {
		t.Run(string(topology), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			plan := transporttest.ProfilePlan{Cold: transporttest.ColdPlan{OperationDeadlineSeconds: 53, PhaseDeadlineSeconds: 60, MaxInflight: 1}}
			endpoint, err := OpenTestEndpointAt(ctx, topology, "127.0.0.1", plan)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				if err := endpoint.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			operation, stop := context.WithTimeout(ctx, 53*time.Second)
			defer stop()
			pair, err := endpoint.Connect(operation)
			if err != nil {
				t.Fatal(err)
			}
			if len(pair.reporters) != 3 {
				t.Fatal("profile lost an independently installed original authority")
			}
			for _, reporter := range pair.reporters {
				if reporter.AuthorityOperationMS() != 53000 {
					t.Fatal("original authority lost the complete profile operation deadline")
				}
			}
			payload := []byte("original-53-second-profile")
			response, err := pair.CallEcho(operation, payload)
			if err != nil || !bytes.Equal(response, payload) {
				t.Fatalf("original long-profile service: %q %v", response, err)
			}
		})
	}
}

func TestCurrentTunnelProfilesRejectUnsupportedPreparationWindows(t *testing.T) {
	plan := transporttest.ProfilePlan{Cold: transporttest.ColdPlan{OperationDeadlineSeconds: 91, PhaseDeadlineSeconds: 92, MaxInflight: 1}}
	if endpoint, err := OpenTestEndpointAt(context.Background(), TopologyQQ, "127.0.0.1", plan); err == nil {
		endpoint.Close(context.Background())
		t.Fatal("accepted an operation beyond the original preparation window")
	}
	if endpoint, err := OpenBrowserTestEndpointAt(context.Background(), BrowserTunnelWTQUIC, "127.0.0.1", "https://127.0.0.1", plan); err == nil {
		endpoint.Close(context.Background())
		t.Fatal("accepted a browser operation beyond the original preparation window")
	}
}
