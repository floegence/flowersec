package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// ConnectionAttemptFacts is a detached projection of observations retained by
// the original Session and spend owners. Unknown means no owner supplied proof.
type ConnectionAttemptFacts struct {
	Phase              string
	Spent              *bool
	SpendState         string
	AdmissionState     string
	NetworkReady       string
	ApplicationPublish string
	SourceProfile      string
	QueryAvailability  string
}

type ConnectionDiagnosticFailure struct {
	Phase string
	Code  string
}

type ConnectionCleanupStatus struct {
	Status           string
	CoreCleanup      string
	PendingCallbacks uint64
}

// ConnectionDiagnostic contains only finite local outcomes and detached facts.
type ConnectionDiagnostic struct {
	State            string
	Attempt          uint64
	Failure          *ConnectionDiagnosticFailure
	Connection       *ConnectionAttemptFacts
	Cleanup          ConnectionCleanupStatus
	RetryDisposition string
}

// LocalReport explains only an already-recorded result. Numeric capacity
// evidence remains absent unless an owner measures it.
type LocalReport struct {
	Code        string
	Constraint  string
	Required    *uint64
	Available   *uint64
	Reservation string
	Connection  ConnectionAttemptFacts
	Cleanup     ConnectionCleanupStatus
	Actions     []string
}

func (s *EnvironmentSession) ConnectionAttemptFacts() ConnectionAttemptFacts {
	facts := ConnectionAttemptFacts{Phase: "unknown", SpendState: "unknown", AdmissionState: "unknown",
		NetworkReady: "unknown", ApplicationPublish: "unknown", QueryAvailability: "unavailable"}
	if s == nil {
		return facts
	}
	s.mu.Lock()
	profile, observation, admissionState := s.diagnosticSourceProfile, s.spendObservation, s.admissionState
	ready, published := s.diagnosticNetworkReady, channelClosed(s.published)
	if s.controllerManaged {
		published = s.controllerApplicationPublished
	}
	failed := s.closed && s.result != nil
	s.mu.Unlock()
	facts.SourceProfile = profile
	if admissionState != "" {
		facts.AdmissionState = admissionState
		facts.NetworkReady, facts.ApplicationPublish = "not_started", "not_started"
	}
	if failed && facts.AdmissionState == "in_flight" {
		facts.AdmissionState = "unknown"
	}
	if observation != nil {
		status := observation.Snapshot()
		if status.Bound {
			switch {
			case status.CommitKnown:
				spent := true
				facts.Spent, facts.SpendState = &spent, "spent"
			case !status.Started:
				spent := false
				facts.Spent, facts.SpendState = &spent, "unspent"
			}
		}
	}
	// A verified FSA4 or authenticated dual READY is positive proof of this
	// admission's original spend, including live-authority and accepted paths
	// that have no client-side PoolSpendObservation.
	if facts.AdmissionState == "admitted" || ready {
		spent := true
		facts.Spent, facts.SpendState = &spent, "spent"
		facts.AdmissionState = "admitted"
	}
	if ready {
		facts.NetworkReady = "ready"
	}
	if published {
		facts.ApplicationPublish = "published"
	}
	if failed && !published && ready {
		facts.ApplicationPublish = "failed"
	}
	switch {
	case ready:
		facts.Phase = "ready"
	case facts.AdmissionState == "admitted":
		facts.Phase = "admitted_not_ready"
	case facts.SpendState == "spent" && facts.AdmissionState == "not_started":
		facts.Phase = "spent_not_admitted"
	case facts.SpendState == "unspent" && facts.AdmissionState == "not_started":
		facts.Phase = "not_started"
	}
	return facts
}

func (s *EnvironmentSession) ConnectionDiagnostic() ConnectionDiagnostic {
	if s == nil {
		return ConnectionDiagnostic{State: "unavailable", RetryDisposition: "terminal"}
	}
	s.mu.Lock()
	state := "connecting"
	if s.closed {
		state = "closed"
	} else if s.diagnosticNetworkReady {
		state = "connected"
	}
	phase, cause, failed := s.diagnosticPhase, s.result, s.closed && s.result != nil && (!s.delivered || s.result != cryptov4.ErrClosed)
	attempt := s.controllerDiagnosticAttempt
	if attempt == 0 {
		attempt = 1
	}
	s.mu.Unlock()
	cleanup := s.CleanupStatus()
	out := ConnectionDiagnostic{State: state, Attempt: attempt, RetryDisposition: "terminal"}
	facts := s.ConnectionAttemptFacts()
	out.Connection = &facts
	out.Cleanup = cleanupProjection(cleanup)
	if failed {
		code := safeDiagnosticFailureCode(cause)
		failurePhase := "connect"
		if phase >= diagnosticv4.PhaseApplication {
			failurePhase = "session"
		}
		out.Failure = &ConnectionDiagnosticFailure{Phase: failurePhase, Code: code}
	}
	return out
}

func (s *EnvironmentSession) LocalReport() LocalReport {
	diagnostic := s.ConnectionDiagnostic()
	connection := ConnectionAttemptFacts{Phase: "unknown", SpendState: "unknown", AdmissionState: "unknown",
		NetworkReady: "unknown", ApplicationPublish: "unknown", QueryAvailability: "unavailable"}
	if diagnostic.Connection != nil {
		connection = *diagnostic.Connection
	}
	code, constraint := "unknown", "unavailable"
	if diagnostic.Failure != nil {
		code = diagnostic.Failure.Code
		if code == "resource_exhausted" || code == "reservation_conflict" {
			constraint = "resource"
		} else if code == "other" {
			constraint = "unavailable"
		}
	}
	return LocalReport{Code: code, Constraint: constraint, Reservation: "not_reserved",
		Connection: connection, Cleanup: diagnostic.Cleanup, Actions: []string{}}
}

func cleanupProjection(status protocolv4.V4CleanupStatus) ConnectionCleanupStatus {
	return ConnectionCleanupStatus{Status: string(status.Status), CoreCleanup: string(status.CoreCleanup), PendingCallbacks: status.PendingCallbacks}
}

func safeDiagnosticFailureCode(cause error) (code string) {
	code = "other"
	defer func() {
		if recover() != nil {
			code = "other"
		}
	}()
	value, _ := diagnosticFailure(cause)
	return value.String()
}

func channelClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// detachedDiagnostic never returns pointers into the Controller's retained
// snapshot. Compact diagnostics carry no Session, provider or retry authority.
func detachedDiagnostic(input ConnectionDiagnostic) ConnectionDiagnostic {
	output := input
	if input.Failure != nil {
		failure := *input.Failure
		output.Failure = &failure
	}
	if input.Connection != nil {
		facts := *input.Connection
		if facts.Spent != nil {
			spent := *facts.Spent
			facts.Spent = &spent
		}
		output.Connection = &facts
	}
	return output
}

func unknownAttemptDiagnostic(attempt uint64) ConnectionDiagnostic {
	return ConnectionDiagnostic{State: "connecting", Attempt: attempt, RetryDisposition: "terminal",
		Connection: &ConnectionAttemptFacts{Phase: "unknown", SpendState: "unknown", AdmissionState: "unknown",
			NetworkReady: "unknown", ApplicationPublish: "unknown", QueryAvailability: "unavailable"}}
}

func (c *ConnectionController) ConnectionDiagnostic() ConnectionDiagnostic {
	if c == nil {
		return ConnectionDiagnostic{State: "unavailable", RetryDisposition: "terminal"}
	}
	c.mu.Lock()
	current := c.current
	session := current
	// The currently establishing replacement owns the latest connection facts,
	// even while its predecessor continues to serve previously bound handles.
	pending, initializing := false, false
	if c.attempt != nil {
		pending, initializing = !c.attempt.finished, c.attempt.entered && !c.attempt.finished
		// Even a failed attempt that never attached a candidate owns the
		// latest attempt. Its predecessor cannot supply that attempt's facts.
		if !c.attempt.result.CurrentSwitched {
			session = c.attempt.candidate
		}
	}
	last, hasLast := c.lastDiagnostic, c.hasLastDiagnostic
	attempts, retry, notBefore := c.serial, c.retryWindow != nil || c.retryPending, c.retryNotBefore
	closed, blocked, cause := c.closed, c.blocked, c.lastError
	c.mu.Unlock()
	out := unknownAttemptDiagnostic(attempts)
	if session != nil {
		observed := session.ConnectionDiagnostic()
		if observed.Attempt == attempts || attempts == 0 {
			out = observed
		}
	}
	if !pending && hasLast && (session == nil || cause != nil && session == current) {
		out = detachedDiagnostic(last)
	}
	out.Attempt = attempts
	if attempts == 0 && session != nil {
		out.Attempt = 1
	}
	out.Cleanup = cleanupProjection(c.CleanupStatus())
	if pending {
		out.State = "connecting"
		if initializing {
			out.State = "initializing"
		}
	}
	if cause != nil && !pending {
		out.State = "failed"
		code, phase := safeDiagnosticFailureCode(cause), "controller"
		if blocked {
			code, phase = "initialization_failed", "session"
		}
		out.Failure = &ConnectionDiagnosticFailure{Phase: phase, Code: code}
	}
	if retry {
		out.State, out.RetryDisposition = "waiting", "retryable"
		if notBefore != 0 {
			out.RetryDisposition = "retry_after"
		}
	}
	if closed {
		out.State, out.RetryDisposition = "closed", "terminal"
	}
	return out
}

func (c *ConnectionController) LocalReport() LocalReport {
	diagnostic := c.ConnectionDiagnostic()
	connection := ConnectionAttemptFacts{Phase: "unknown", SpendState: "unknown", AdmissionState: "unknown",
		NetworkReady: "unknown", ApplicationPublish: "unknown", QueryAvailability: "unavailable"}
	if diagnostic.Connection != nil {
		connection = *diagnostic.Connection
	}
	code, constraint := "unknown", "unavailable"
	if diagnostic.Failure != nil {
		code, constraint = diagnostic.Failure.Code, "connection"
	}
	return LocalReport{Code: code, Constraint: constraint, Reservation: "not_reserved",
		Connection: connection, Cleanup: diagnostic.Cleanup, Actions: []string{}}
}
