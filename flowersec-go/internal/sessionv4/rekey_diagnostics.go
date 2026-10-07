package sessionv4

import (
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func (t *rekeyTiming) startDiagnostics(counters *diagnosticv4.Counters, operations ...*DiagnosticOperation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.diagnostics = counters
	if len(operations) != 0 {
		t.diagnosticOperation = operations[0]
	}
	fields := diagnosticv4.Fields{State: diagnosticv4.StateReady, Phase: t.diagnosticPhase(), Code: diagnosticv4.CodeOK}
	if counters != nil {
		counters.Observe(diagnosticv4.MetricRekeyStarted, fields)
	}
	if t.diagnosticOperation != nil {
		t.diagnosticOperation.Emit(fields)
	}
}

func (t *rekeyTiming) diagnosticPhase() diagnosticv4.Phase {
	switch t.stage {
	case 0:
		return diagnosticv4.PhaseRekeyLocalPrepare
	case 1:
		return diagnosticv4.PhaseRekeyProtocolPrepare
	case 2:
		return diagnosticv4.PhaseRekeyConfirmation
	default:
		return diagnosticv4.PhaseOther
	}
}

// The watchdog and publication worker share the original phase gate. Repeated
// checks of one expired round contribute one timeout, including when the
// provider is still blocked. Manual cancellation retains that same observation.
func (t *rekeyTiming) observeTimeoutLocked(err error) {
	if err != cryptov4.ErrExpired && err != timev4.ErrExpired || t.timeoutObserved {
		return
	}
	t.timeoutObserved = true
	fields := diagnosticv4.Fields{State: diagnosticv4.StateFailed, Phase: t.diagnosticPhase(), Code: diagnosticv4.CodeTimeout}
	if t.diagnostics != nil {
		t.diagnostics.Observe(diagnosticv4.MetricRekeyTimeout, fields)
	}
	if t.diagnosticOperation != nil {
		t.diagnosticOperation.Emit(fields)
	}
}

func (t *rekeyTiming) checkPhase() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.phase == nil || t.stage == 3 {
		return nil
	}
	err := t.phase.Check()
	t.observeTimeoutLocked(err)
	return err
}

func (t *rekeyTiming) observePhaseLocked(now timev4.Sample) {
	// Use the original monotonic samples for observation only. Clamp before the
	// duration conversion; do not resample or change any security deadline.
	duration := diagnosticv4.Duration(time.Duration(min(now.Milliseconds-t.anchor.Milliseconds, 10000)) * time.Millisecond)
	fields := diagnosticv4.Fields{State: diagnosticv4.StateReady, Phase: t.diagnosticPhase(), Code: diagnosticv4.CodeOK,
		DurationBucket: duration}
	if t.diagnostics != nil {
		t.diagnostics.Observe(diagnosticv4.MetricRekeyPhaseCompleted, fields)
	}
	if t.diagnosticOperation != nil {
		t.diagnosticOperation.Emit(fields)
	}
}

func (t *rekeyTiming) finishDiagnostics(completed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if completed {
		fields := diagnosticv4.Fields{State: diagnosticv4.StateReady, Phase: diagnosticv4.PhaseRekeyConfirmation, Code: diagnosticv4.CodeOK}
		if t.diagnostics != nil {
			t.diagnostics.Observe(diagnosticv4.MetricRekeySucceeded, fields)
		}
		if t.diagnosticOperation != nil {
			t.diagnosticOperation.Emit(fields)
		}
	}
	// Old exchange aliases cannot retain the Environment bank after the round
	// releases its owner. Active tails still retain their original protocol graph.
	t.diagnostics = nil
	t.diagnosticOperation = nil
}
