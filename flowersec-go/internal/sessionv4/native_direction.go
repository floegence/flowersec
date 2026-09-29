package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
)

// Preserve a previously completed native FIN. Abrupt cleanup remains available
// for directions which have not actually ended, and never creates a proof.
func closeNativeStream(stream native.Stream) {
	if actual, ok := stream.(native.DirectionalStream); ok {
		if actual.CloseDirections() == nil {
			return
		}
	}
	_ = stream.Close()
}

// A concrete native direction signal is scoped to its existing association.
// During OPEN only normal_drained is a bounded hint; the original deadline
// and pending outcome remain, with no DATA permission or successful result.
func (a *OpenAdmission) nativeWriteFailure(scope uint64, cause error) bool {
	if cause != native.ErrNormalDrained && cause != native.ErrDirectionReset {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(OpenHandle{a, scope})
	if err != nil || a.closed || s.carrier == nil || s.carrier.native == nil {
		return false
	}
	if s.local && s.submitted && s.phase == openOpening && cause == native.ErrNormalDrained {
		s.nativeSendStopped = true
		return true
	}
	if s.accepted && (s.phase == openLive || s.phase == openRecent) {
		s.nativeSendStopped = true
		if s.flow != nil {
			s.flow.send.nativeStopped(cause)
		}
		return true
	}
	return false
}

// Seal native publication after the provider has physically stopped receiving.
// The authenticated frontier and its original terminal deadline still decide
// completion. A normal hint cannot manufacture success or overwrite a proof.
func (f *SendFlow) nativeStopped(cause error) {
	f.mu.Lock()
	f.stopping = true
	if !f.wireDone {
		f.termination.start(cause != native.ErrNormalDrained, cause)
	}
	if !f.active && !f.hasTerminal {
		f.terminal, f.hasTerminal = f.frontier, true
	}
	f.reservation.Seal()
	f.signalCleanupLocked()
	queue := f.queue
	f.mu.Unlock()
	f.writer.Close()
	if queue != nil {
		queue.stopFromFlow(cause)
	}
}
