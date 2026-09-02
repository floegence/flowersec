//go:build linux

package flowersecweaknet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv3"
)

func TestRepresentativeScenarioConfiguresThePeriodicLossItValidates(t *testing.T) {
	scenario, err := scenarioFor("representative")
	if err != nil {
		t.Fatal(err)
	}
	if scenario.profile.LossMode != "periodic" || scenario.profile.EveryNth != 100 || scenario.profile.OutageDuration != 0 {
		t.Fatalf("representative profile = %+v", scenario.profile)
	}
}

func TestControllerWeaknetScenariosHaveDistinctNamespaceSuffixes(t *testing.T) {
	seen := map[string]string{}
	for _, name := range []string{"delay-jitter", "periodic-loss", "reorder", "outage-reconnect", "pin-rotation-refresh-backoff-lease"} {
		suffix := shortScenario(name)
		if suffix == "" {
			t.Fatalf("controller scenario %q has no namespace suffix", name)
		}
		if previous := seen[suffix]; previous != "" {
			t.Fatalf("controller scenarios %q and %q share namespace suffix %q", previous, name, suffix)
		}
		seen[suffix] = name
	}
}

func TestRateScenariosFreezeObservableTransferDurations(t *testing.T) {
	for name, minimum := range map[string]time.Duration{"rate-5mbps": 320 * time.Millisecond, "rate-1mbps": 1700 * time.Millisecond} {
		scenario, err := scenarioFor(name)
		if err != nil {
			t.Fatal(err)
		}
		if scenario.minimumTransferDuration < minimum {
			t.Fatalf("%s minimum transfer duration = %s", name, scenario.minimumTransferDuration)
		}
		want := shapedTransferMinimum(scenario.profile.RateBitsPerSecond, scenario.profile.TokenBurstBytes, scenario.payloadBytes)
		if scenario.minimumTransferDuration != want {
			t.Fatalf("%s minimum duration = %s, want derived %s", name, scenario.minimumTransferDuration, want)
		}
	}
}

func TestMTUScenarioRequiresRoutedPMTUDiscovery(t *testing.T) {
	scenario, err := scenarioFor("mtu-large-payload")
	if err != nil {
		t.Fatal(err)
	}
	if scenario.profile.LinkMTU != 1500 || scenario.pathMTU != 1280 {
		t.Fatalf("MTU scenario = %+v", scenario)
	}
	for name, probe := range map[string]pathMTUProbe{
		"learned": func(context.Context, string, string) (int, error) { return 1280, nil },
		"missing": func(context.Context, string, string) (int, error) { return 1500, nil },
		"failed":  func(context.Context, string, string) (int, error) { return 0, errors.New("probe failed") },
	} {
		err := verifyPathMTU(context.Background(), "client", "198.19.0.2", 1280, probe)
		if name == "learned" && err != nil {
			t.Fatalf("learned PMTU rejected: %v", err)
		}
		if name != "learned" && err == nil {
			t.Fatalf("%s PMTU probe accepted", name)
		}
	}
}

func TestRequiredWeaknetEnvironmentRejectsMissingIntegration(t *testing.T) {
	if err := validateWeaknetEnvironment(true, ""); err == nil {
		t.Fatal("required weaknet accepted a missing Linux integration environment")
	}
	if err := validateWeaknetEnvironment(true, "1"); err != nil {
		t.Fatal(err)
	}
}

type resetReader struct{ err error }

func (reader resetReader) Read([]byte) (int, error) { return 0, reader.err }
func (resetReader) Close() error                    { return nil }

func TestPeerResetObservationRequiresTheRemoteTerminalError(t *testing.T) {
	if err := observePeerReset(context.Background(), resetReader{err: protocolv3.ErrStreamReset}); err != nil {
		t.Fatal(err)
	}
	if err := observePeerReset(context.Background(), resetReader{err: errors.New("closed without reset")}); err == nil {
		t.Fatal("peer close without reset was accepted")
	}
}

func TestTunnelFailureCleanupSuppliesABoundedDeadlineToEveryOwner(t *testing.T) {
	calls := 0
	checkDeadline := func(ctx context.Context) error {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
			return errors.New("cleanup context is not bounded")
		}
		return nil
	}
	if err := cleanupTunnelFailure(checkDeadline, checkDeadline); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("cleanup owners called %d times", calls)
	}
}

func TestUnreliableAcceptanceAccumulatesAcrossRetries(t *testing.T) {
	accepted := false
	accepted = accumulateUnreliableAcceptance(accepted, true)
	accepted = accumulateUnreliableAcceptance(accepted, false)
	if !accepted {
		t.Fatal("later dropped attempt erased an earlier accepted send")
	}
}
