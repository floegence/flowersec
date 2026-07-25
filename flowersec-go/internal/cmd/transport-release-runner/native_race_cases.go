package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

const quicNativeRaceOwner = "quic-native-race"

var nativeRaceCoreCases = []releaseCaseDefinition{
	{ID: "NS-N2", Profile: "native-flow-isolation", Carrier: carrier.KindQUIC},
	{ID: "NS-N3", Profile: "native-reset-isolation", Carrier: carrier.KindQUIC},
}

var nativeRaceCases = []releaseCaseDefinition{
	{ID: "BN-N5", Profile: "webtransport-native-isolation", BrowserTopology: browserDirectTopology},
	{ID: "NP-REBIND", Profile: "native-rebind", Carrier: carrier.KindQUIC},
	{ID: "NS-N2", Profile: "native-flow-isolation", Carrier: carrier.KindQUIC},
	{ID: "NS-N3", Profile: "native-reset-isolation", Carrier: carrier.KindQUIC},
}

func runNativeRaceCase(ctx context.Context, destination *artifactDestination, definition releaseCaseDefinition, mode, sourceRoot, bpfObject string, plan transportrelease.ReleasePlan) (releaseCaseResult, error) {
	if mode != "race" || !raceDetectorEnabled() {
		return releaseCaseResult{}, errors.New("native race cases require a race-instrumented runner")
	}
	switch definition.ID {
	case "BN-N5":
		return runBrowserSmokeCase(ctx, destination, definition, mode, sourceRoot, plan)
	case "NP-REBIND":
		return runNativeProofSystemCase(ctx, destination, definition, mode, bpfObject)
	}
	capture, err := startNativeQLOGCapture()
	if err != nil {
		return releaseCaseResult{}, err
	}
	started := time.Now()
	var run nativeCaseRun
	switch definition.ID {
	case "NS-N2":
		run, err = runNativeFlowIsolation(ctx)
	case "NS-N3":
		run, err = runNativeResetIsolation(ctx)
	default:
		err = fmt.Errorf("unknown native race case %s", definition.ID)
	}
	expectedStreamIDs := make([]int64, 0, len(run.observations))
	for _, observation := range run.observations {
		expectedStreamIDs = append(expectedStreamIDs, observation.streamID)
	}
	qlog, connectionID, captureErr := capture.finish(expectedStreamIDs)
	if err = errors.Join(err, captureErr); err != nil {
		return releaseCaseResult{}, err
	}
	run.qlog, run.connectionID = qlog, connectionID
	elapsed := time.Since(started)
	written, err := writeNativeCaseArtifacts(destination, definition, mode, run, elapsed)
	if err != nil {
		return releaseCaseResult{}, err
	}
	return releaseCaseResult{
		ID: definition.ID, Profile: definition.Profile, Status: "pass", CompletedOperations: run.completed,
		ElapsedNanoseconds: elapsed.Nanoseconds(), Artifacts: written.Artifacts, RawSources: written.RawSources,
	}, nil
}
