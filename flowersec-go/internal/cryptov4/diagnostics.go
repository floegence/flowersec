package cryptov4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Classify only a completely parsed DATAGRAM, at its original ingress epoch.
// A staged/future epoch is not counted as an old or current datagram.
func (e *Engine) datagramDropMetricLocked(frame protocolv4.FrameType, header protocolv4.RecordHeader) diagnosticv4.Metric {
	if frame != protocolv4.FrameDatagram || e.current == nil {
		return diagnosticv4.MetricOther
	}
	if header.Epoch < e.current.number {
		return diagnosticv4.MetricOldDatagramDrop
	}
	if header.Epoch > e.current.number {
		return diagnosticv4.MetricFutureDatagramDrop
	}
	return diagnosticv4.MetricCurrentDatagramDrop
}

// Called at the rejection gate, before releasing the original work backing.
// The observation performs bounded atomic additions only and affects no AEAD,
// replay window, receive pause, epoch, or authorization outcome.
func (e *Engine) observeDatagramDropLocked(metric diagnosticv4.Metric) {
	var code diagnosticv4.Code
	switch metric {
	case diagnosticv4.MetricCurrentDatagramDrop:
		code = diagnosticv4.CodeCurrentDatagramDropped
	case diagnosticv4.MetricOldDatagramDrop:
		code = diagnosticv4.CodeOldDatagramDropped
	case diagnosticv4.MetricFutureDatagramDrop:
		code = diagnosticv4.CodeFutureDatagramDropped
	default:
		return
	}
	state := diagnosticv4.StateReady
	if e.closed {
		state = diagnosticv4.StateClosed
	} else if !e.ready {
		state = diagnosticv4.StateStarting
	}
	fields := diagnosticv4.Fields{State: state, Phase: diagnosticv4.PhaseApplication, Code: code}
	if e.config.Diagnostics != nil {
		e.config.Diagnostics.Observe(metric, fields)
	}
	if e.config.DiagnosticEvents != nil {
		e.config.DiagnosticEvents.EmitDiagnostic(fields)
	}
}
