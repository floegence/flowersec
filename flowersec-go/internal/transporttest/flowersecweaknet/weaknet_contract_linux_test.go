//go:build linux

package flowersecweaknet

import (
	"context"
	"errors"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest/linuxnetlab"
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
	if err := observePeerReset(context.Background(), resetReader{err: native.ErrDirectionReset}); err != nil {
		t.Fatal(err)
	}
	if err := observePeerReset(context.Background(), resetReader{err: errors.New("closed without reset")}); err == nil {
		t.Fatal("peer close without reset was accepted")
	}
}

func TestControllerOutageRequiresAQualifiedLivenessFailure(t *testing.T) {
	const timeoutMS = uint64(250)
	for name, err := range map[string]error{
		"timeout": errors.New("probe timed out"),
		"cancel":  context.Canceled,
		"closed":  &flowersec.SessionError{},
	} {
		if isQualifiedControllerOutage(flowersec.LivenessResult{}, err, context.Background(), timeoutMS) {
			t.Fatalf("%s was accepted without a qualified session outcome", name)
		}
	}
	for _, code := range []flowersec.SessionErrorCode{flowersec.SessionLivenessFailed, flowersec.SessionClosed} {
		cases := map[string]flowersec.LivenessResult{
			"empty":       {},
			"unsubmitted": {Cause: &flowersec.SessionError{}},
			"no cause":    {Submitted: true},
			"published":   {Submitted: true, Complete: true, Cause: &flowersec.SessionError{}},
			"qualified":   {Submitted: true, Cause: &flowersec.SessionError{}},
		}
		for name, result := range cases {
			accepted := isQualifiedControllerOutageCode(code, code, result, context.Background(), timeoutMS)
			want := name == "qualified" || name == "published"
			if accepted != want {
				t.Fatalf("%s %s accepted = %t, want %t", name, code, accepted, want)
			}
		}
	}

	expiredSubmittedProbe := flowersec.LivenessResult{
		Submitted: true, Complete: true, ElapsedAvailable: true, ElapsedMilliseconds: timeoutMS, Cause: &flowersec.SessionError{},
	}
	if !isQualifiedControllerOutageCode(flowersec.SessionTimeout, flowersec.SessionTimeout, expiredSubmittedProbe, context.Background(), timeoutMS) {
		t.Fatal("submitted probe that exhausted its own operation window was rejected")
	}
	expiredSubmittedProbe.Complete = false
	if !isQualifiedControllerOutageCode(flowersec.SessionTimeout, flowersec.SessionTimeout, expiredSubmittedProbe, context.Background(), timeoutMS) {
		t.Fatal("submitted probe with an outstanding publication tail was rejected")
	}
	invalidTimeouts := map[string]flowersec.LivenessResult{
		"not submitted":             {ElapsedAvailable: true, ElapsedMilliseconds: timeoutMS, Cause: &flowersec.SessionError{}},
		"elapsed unavailable":       {Submitted: true, Cause: &flowersec.SessionError{}},
		"before operation deadline": {Submitted: true, ElapsedAvailable: true, ElapsedMilliseconds: timeoutMS - 1, Cause: &flowersec.SessionError{}},
		"no cause":                  {Submitted: true, ElapsedAvailable: true, ElapsedMilliseconds: timeoutMS},
	}
	for name, result := range invalidTimeouts {
		if isQualifiedControllerOutageCode(flowersec.SessionTimeout, flowersec.SessionTimeout, result, context.Background(), timeoutMS) {
			t.Fatalf("%s was accepted as an operation timeout", name)
		}
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	for _, code := range []flowersec.SessionErrorCode{flowersec.SessionTimeout, flowersec.SessionClosed, flowersec.SessionLivenessFailed} {
		for _, callerCtx := range []context.Context{nil, expired} {
			if isQualifiedControllerOutageCode(code, code, expiredSubmittedProbe, callerCtx, timeoutMS) {
				t.Fatalf("invalid caller was accepted as %s", code)
			}
		}
		if isQualifiedControllerOutageCode(code, flowersec.SessionCanceled, expiredSubmittedProbe, context.Background(), timeoutMS) {
			t.Fatalf("mismatched cause was accepted as %s", code)
		}
	}
	if isQualifiedControllerOutageCode(flowersec.SessionTimeout, flowersec.SessionTimeout, expiredSubmittedProbe, context.Background(), 0) {
		t.Fatal("missing original deadline was accepted as a liveness timeout")
	}
}

func TestOutageObservationRequiresDropsInBothDirections(t *testing.T) {
	base := linuxnetlab.KernelFaultObservation{
		Client: linuxnetlab.KernelFaultStats{Packets: 1, DelayPackets: 1, OutageDropPackets: 1},
		Server: linuxnetlab.KernelFaultStats{Packets: 1, DelayPackets: 1, OutageDropPackets: 1},
	}
	for _, scenario := range []string{"outage", "outage-reconnect"} {
		if err := validateObservation(scenario, base); err != nil {
			t.Fatal(err)
		}
		clientOnly, serverOnly := base, base
		clientOnly.Server.OutageDropPackets = 0
		serverOnly.Client.OutageDropPackets = 0
		for name, observation := range map[string]linuxnetlab.KernelFaultObservation{"client only": clientOnly, "server only": serverOnly} {
			if err := validateObservation(scenario, observation); err == nil {
				t.Fatalf("%s accepted %s outage observation", scenario, name)
			}
		}
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
