package flowersecweaknet

import (
	"context"
	"errors"
	"sync"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
)

type outageProbeOutcome struct {
	result    flowersec.LivenessResult
	err       error
	qualified bool
}

// Each fault direction has its own first-packet window. Independent PINGs
// exercise both directions even when a dropped PING cannot produce a PONG.
// Join both original calls before returning, including on cancellation.
func probeOutageDirections(ctx context.Context, probes [2]func(context.Context, uint64) (flowersec.LivenessResult, error), timeoutMS uint64, callerTimeout time.Duration) (outcomes [2]outageProbeOutcome) {
	var pending sync.WaitGroup
	pending.Add(len(probes))
	for index, probe := range probes {
		go func() {
			defer pending.Done()
			probeCtx, cancel := context.WithTimeout(ctx, callerTimeout)
			defer cancel()
			result, err := probe(probeCtx, timeoutMS)
			outcomes[index] = outageProbeOutcome{result: result, err: err, qualified: isQualifiedControllerOutage(result, err, probeCtx, timeoutMS)}
		}()
	}
	pending.Wait()
	return outcomes
}

func isQualifiedControllerOutage(result flowersec.LivenessResult, err error, callerCtx context.Context, timeoutMS uint64) bool {
	var sessionErr *flowersec.SessionError
	if err == nil || !errors.As(err, &sessionErr) || result.Cause == nil {
		return false
	}
	return isQualifiedControllerOutageCode(sessionErr.Code(), result.Cause.Code(), result, callerCtx, timeoutMS)
}

func isQualifiedControllerOutageCode(code, causeCode flowersec.SessionErrorCode, result flowersec.LivenessResult, callerCtx context.Context, timeoutMS uint64) bool {
	if callerCtx == nil || callerCtx.Err() != nil || !result.Submitted || result.Cause == nil || code != causeCode {
		return false
	}
	switch code {
	case flowersec.SessionLivenessFailed, flowersec.SessionClosed:
		return true
	case flowersec.SessionTimeout:
		return timeoutMS > 0 && result.ElapsedAvailable && result.ElapsedMilliseconds >= timeoutMS
	default:
		return false
	}
}
