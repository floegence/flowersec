package sessionv4

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// DiagnosticCounts returns a finite, detached, unsampled observation. It is not
// an authorization or cleanup fact. The whole bank belongs to EnvironmentCharge.
func (e *Environment) DiagnosticCounts(metric diagnosticv4.Metric) diagnosticv4.Counts {
	if e == nil {
		return diagnosticv4.Counts{}
	}
	return e.counters.Snapshot(metric)
}

// beginDiagnostics runs only when the original position is installed, before
// either of its tasks starts. Preparation handoffs reuse that same attempt.
func (s *EnvironmentSession) beginDiagnostics() {
	s.diagnosticStarted = time.Now()
	s.diagnosticPhase = diagnosticv4.PhasePrepare
	s.environment.counters.Observe(diagnosticv4.MetricConnectionAttempt, diagnosticv4.Fields{
		State: diagnosticv4.StateStarting, Phase: s.diagnosticPhase,
		Code: diagnosticv4.CodeOK, AttemptBucket: diagnosticv4.AttemptOne,
	})
}

func (s *EnvironmentSession) setDiagnosticPhase(phase diagnosticv4.Phase) {
	s.mu.Lock()
	if !s.closed {
		s.diagnosticPhase = phase
	}
	s.mu.Unlock()
}

// diagnosticFailure uses only exact sentinels and a bounded set of native
// wrappers. Error/Is/As/Unwrap methods on arbitrary provider/application values
// must never execute inside the original Session gate. Unknown remains other.
func diagnosticFailure(cause error) (diagnosticv4.Code, diagnosticv4.Metric) {
	for range 8 {
		switch cause {
		case tlspolicy.ErrCertificate:
			return diagnosticv4.CodeTLSRejected, diagnosticv4.MetricTLSRejection
		case protocolv4.CBORFailure("admission_identity_binding"), protocolv4.CBORFailure("credential_identity_binding"), protocolv4.CBORFailure("credential_grant_identity"), protocolv4.CBORFailure("handshake_identity_key"):
			return diagnosticv4.CodeIdentityRejected, diagnosticv4.MetricIdentityRejection
		case ledgerv4.ErrUnknown:
			return diagnosticv4.CodeSpendUnknown, diagnosticv4.MetricSpendUnknown
		case ledgerv4.ErrStorageUnavailable, ledgerv4.ErrStorageFormat:
			return diagnosticv4.CodeStoreUnavailable, diagnosticv4.MetricStoreFailure
		case ledgerv4.ErrConflict:
			return diagnosticv4.CodeReservationConflict, diagnosticv4.MetricReservationConflict
		case resourcev4.ErrCapacity, cryptov4.ErrCapacity, ledgerv4.ErrCapacity:
			return diagnosticv4.CodeResourceExhausted, diagnosticv4.MetricResourceRejection
		case context.DeadlineExceeded, timev4.ErrExpired, cryptov4.ErrExpired:
			return diagnosticv4.CodeTimeout, diagnosticv4.MetricOther
		case context.Canceled:
			return diagnosticv4.CodeCancelled, diagnosticv4.MetricOther
		}
		switch value := cause.(type) {
		case *tls.CertificateVerificationError:
			if value != nil {
				return diagnosticv4.CodeTLSRejected, diagnosticv4.MetricTLSRejection
			}
		case *net.OpError:
			if value != nil {
				cause = value.Err
				continue
			}
		case *url.Error:
			if value != nil {
				cause = value.Err
				continue
			}
		}
		break
	}
	return diagnosticv4.CodeOther, diagnosticv4.MetricOther
}

// observeClosure is called once, at the original closed transition. A normal
// delivered Close does not become a failure. A failed delivery is an attempt
// failure even when the owner was explicitly closed before READY publication.
func (s *EnvironmentSession) observeClosure(cause error) {
	if s.environment == nil || s.diagnosticStarted.IsZero() ||
		s.delivered && (cause == nil || cause == cryptov4.ErrClosed) {
		return
	}
	code, metric := diagnosticFailure(cause)
	fields := diagnosticv4.Fields{State: diagnosticv4.StateFailed, Phase: s.diagnosticPhase,
		Code: code, AttemptBucket: diagnosticv4.AttemptOne,
		DurationBucket:   diagnosticv4.Duration(time.Since(s.diagnosticStarted)),
		RetryDisposition: diagnosticv4.RetryPreserveFacts}
	s.environment.counters.Observe(diagnosticv4.MetricConnectionFailure, fields)
	if metric != diagnosticv4.MetricOther {
		s.environment.counters.Observe(metric, fields)
	}
}

func (e *Environment) observePositionRejection() {
	e.counters.Observe(diagnosticv4.MetricResourceRejection, diagnosticv4.Fields{
		State: diagnosticv4.StateStarting, Phase: diagnosticv4.PhasePrepare,
		Code: diagnosticv4.CodeResourceExhausted,
	})
}

func (s *EnvironmentSession) observeCleanupTimeout(cause error) {
	if cause != context.DeadlineExceeded {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned || s.cleanupTimeoutObserved || s.environment == nil {
		return
	}
	s.cleanupTimeoutObserved = true
	s.environment.counters.Observe(diagnosticv4.MetricCleanupTimeout, diagnosticv4.Fields{
		State: diagnosticv4.StateClosed, Phase: diagnosticv4.PhaseCleanup,
		Code: diagnosticv4.CodeCleanupIncomplete,
	})
}

func (e *Environment) observeCleanupTimeout(cause error) {
	if cause != context.DeadlineExceeded {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cleaned || e.cleanupTimeoutObserved {
		return
	}
	e.cleanupTimeoutObserved = true
	e.counters.Observe(diagnosticv4.MetricCleanupTimeout, diagnosticv4.Fields{
		State: diagnosticv4.StateClosed, Phase: diagnosticv4.PhaseCleanup,
		Code: diagnosticv4.CodeCleanupIncomplete,
	})
}

// The admission method is already physically active. Its Environment position
// cannot retire until this exact core and all children retire. No additional
// reference, task, clock requirement, or caller-owned callback is introduced.
func (p *SessionCorePlan) bindEnvironmentDiagnostics(host *EnvironmentSession) error {
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.closed || host.environment == nil {
		return cryptov4.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.claimed || p.preparing || p.retired {
		return cryptov4.ErrTransition
	}
	p.diagnostics = &host.environment.counters
	if p.receivePool != nil {
		p.receivePool.mu.Lock()
		if !p.receivePool.closed {
			p.receivePool.diagnostics = p.diagnostics
		}
		p.receivePool.mu.Unlock()
	}
	host.diagnosticPhase = diagnosticv4.PhaseHandshake
	return nil
}

// Count original receive directions that exhaust their unread ring while still
// open. This is local backpressure, not a peer or transport failure; observation
// neither withdraws promised credit nor schedules a reset or new work.
func (f *ReceiveFlow) observeConsumerSaturationLocked() {
	if f.consumerSaturationObserved || f.hasTerminal || f.abandoned || len(f.storage) == 0 || f.size != len(f.storage) || f.pool.diagnostics == nil {
		return
	}
	f.consumerSaturationObserved = true
	f.pool.diagnostics.Observe(diagnosticv4.MetricSlowConsumer, diagnosticv4.Fields{
		State: diagnosticv4.StateReady, Phase: diagnosticv4.PhaseApplication,
		Code: diagnosticv4.CodeSlowConsumer,
	})
}
