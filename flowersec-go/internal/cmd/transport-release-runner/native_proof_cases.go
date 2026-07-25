package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
)

const quicNativeProofOwner = "quic-native-proof"

var nativeProofCoreCases = []releaseCaseDefinition{
	{ID: "NP-FLOW-FULL", Profile: "native-flow-full", Carrier: carrier.KindQUIC},
	{ID: "NP-MAXDATA", Profile: "native-max-data", Carrier: carrier.KindQUIC},
	{ID: "NP-RESET-FIN", Profile: "native-reset-fin", Carrier: carrier.KindQUIC},
	{ID: "NP-STREAM-LIMIT", Profile: "native-stream-limit", Carrier: carrier.KindQUIC},
}

var nativeProofCases = []releaseCaseDefinition{
	{ID: "NP-FLOW-FULL", Profile: "native-flow-full", Carrier: carrier.KindQUIC},
	{ID: "NP-MAXDATA", Profile: "native-max-data", Carrier: carrier.KindQUIC},
	{ID: "NP-PMTUD-STATE", Profile: "userspace-pmtud-state", Carrier: carrier.KindQUIC},
	{ID: "NP-REBIND", Profile: "native-rebind", Carrier: carrier.KindQUIC},
	{ID: "NP-RESET-FIN", Profile: "native-reset-fin", Carrier: carrier.KindQUIC},
	{ID: "NP-STREAM-LIMIT", Profile: "native-stream-limit", Carrier: carrier.KindQUIC},
	{ID: "NP-TARGET-LOSS", Profile: "native-targeted-loss", Carrier: carrier.KindQUIC},
}

func runNativeProofCase(ctx context.Context, destination *artifactDestination, definition releaseCaseDefinition, mode, bpfObject string) (releaseCaseResult, error) {
	switch definition.ID {
	case "NP-PMTUD-STATE", "NP-REBIND", "NP-TARGET-LOSS":
		return runNativeProofSystemCase(ctx, destination, definition, mode, bpfObject)
	default:
		return runNativeProofCoreCase(ctx, destination, definition, mode)
	}
}

func runNativeProofCoreCase(ctx context.Context, destination *artifactDestination, definition releaseCaseDefinition, mode string) (releaseCaseResult, error) {
	if mode != "normal" {
		return releaseCaseResult{}, errors.New("native proof core cases only support normal mode")
	}
	capture, err := startNativeQLOGCapture()
	if err != nil {
		return releaseCaseResult{}, err
	}
	started := time.Now()
	var run nativeCaseRun
	switch definition.ID {
	case "NP-FLOW-FULL":
		run, err = runNativeFlowIsolation(ctx)
	case "NP-RESET-FIN":
		run, err = runNativeResetIsolation(ctx)
	case "NP-MAXDATA":
		run, err = runNativeConnectionFlowControl(ctx)
	case "NP-STREAM-LIMIT":
		run, err = runNativeStreamLimit(ctx)
	default:
		err = fmt.Errorf("unknown native proof core case %s", definition.ID)
	}
	expectedStreamIDs := make([]int64, 0, len(run.observations))
	for _, observation := range run.observations {
		expectedStreamIDs = append(expectedStreamIDs, observation.streamID)
	}
	qlog, connectionID, captureErr := capture.finish(expectedStreamIDs)
	err = errors.Join(err, captureErr)
	if err != nil {
		return releaseCaseResult{}, err
	}
	run.qlog = qlog
	run.connectionID = connectionID
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

func runNativeConnectionFlowControl(ctx context.Context) (nativeCaseRun, error) {
	limits := rawquic.DefaultLimits()
	limits.InitialStreamReceiveWindow = 256 << 10
	limits.MaxStreamReceiveWindow = 256 << 10
	limits.InitialConnectionReceiveWindow = 64 << 10
	limits.MaxConnectionReceiveWindow = 64 << 10
	client, server, closePair, err := openNativeQUICPair(ctx, limits)
	if err != nil {
		return nativeCaseRun{}, err
	}
	defer closePair()
	blocked, err := client.OpenStream(ctx)
	if err != nil {
		return nativeCaseRun{}, err
	}
	blockedID := nativeStreamID(blocked)
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := blocked.Write(make([]byte, 8<<20))
		writeDone <- writeErr
	}()
	accepted := make(chan carrier.Stream, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		stream, acceptErr := server.AcceptStream(ctx)
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- stream
	}()
	var peer carrier.Stream
	select {
	case peer = <-accepted:
	case err := <-acceptErrors:
		return nativeCaseRun{}, err
	case err := <-writeDone:
		return nativeCaseRun{}, fmt.Errorf("connection-limited write completed unexpectedly: %w", err)
	case <-ctx.Done():
		return nativeCaseRun{}, context.Cause(ctx)
	}
	select {
	case err := <-writeDone:
		return nativeCaseRun{}, fmt.Errorf("connection-limited write did not block: %w", err)
	case <-time.After(50 * time.Millisecond):
	case <-ctx.Done():
		return nativeCaseRun{}, context.Cause(ctx)
	}
	_ = blocked.Reset()
	_ = peer.Reset()
	return nativeCaseRun{completed: 1, observations: []nativeApplicationObservation{{event: "native_connection_blocked", streamID: blockedID}}}, nil
}

func runNativeStreamLimit(ctx context.Context) (nativeCaseRun, error) {
	limits := rawquic.DefaultLimits()
	limits.MaxInboundStreams = 2
	client, server, closePair, err := openNativeQUICPair(ctx, limits)
	if err != nil {
		return nativeCaseRun{}, err
	}
	defer closePair()
	opened := make([]carrier.Stream, 0, 2)
	accepted := make([]carrier.Stream, 0, 2)
	observations := make([]nativeApplicationObservation, 0, 2)
	for index := 0; index < 2; index++ {
		stream, openErr := client.OpenStream(ctx)
		if openErr != nil {
			return nativeCaseRun{}, openErr
		}
		if _, writeErr := stream.Write([]byte{byte(index)}); writeErr != nil {
			return nativeCaseRun{}, writeErr
		}
		peer, acceptErr := server.AcceptStream(ctx)
		if acceptErr != nil {
			return nativeCaseRun{}, acceptErr
		}
		opened = append(opened, stream)
		accepted = append(accepted, peer)
		observations = append(observations, nativeApplicationObservation{event: "native_stream_observed", streamID: nativeStreamID(stream)})
	}
	blockedCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	_, blockedErr := client.OpenStream(blockedCtx)
	cancel()
	if !errors.Is(blockedErr, context.DeadlineExceeded) {
		return nativeCaseRun{}, fmt.Errorf("third native stream error = %v, want stream-limit deadline", blockedErr)
	}
	for index := range opened {
		_ = opened[index].Reset()
		_ = accepted[index].Reset()
	}
	return nativeCaseRun{completed: 2, observations: observations}, nil
}
