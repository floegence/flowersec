package flowersec

import "github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"

// ConnectionAttemptFacts is a detached projection of facts retained by the
// original Session and spend owners. Unknown is explicit and never inferred
// from a generic connection error.
type ConnectionAttemptFacts = sessionv4.ConnectionAttemptFacts
type ConnectionDiagnosticFailure = sessionv4.ConnectionDiagnosticFailure
type ConnectionCleanupStatus = sessionv4.ConnectionCleanupStatus

// ConnectionDiagnostic is a finite monitoring projection with no raw errors,
// credentials, endpoints, carriers or Session references.
type ConnectionDiagnostic = sessionv4.ConnectionDiagnostic

// LocalReport explains only already-recorded owner facts. Missing numeric
// capacity evidence remains nil and report creation performs no query.
type LocalReport = sessionv4.LocalReport

func (s *Session) ConnectionAttemptFacts() ConnectionAttemptFacts {
	if s == nil || s.connectionDiagnostic == nil {
		return unknownConnectionFacts()
	}
	diagnostic := s.connectionDiagnostic()
	if diagnostic.Connection == nil {
		return unknownConnectionFacts()
	}
	return *diagnostic.Connection
}

func (s *Session) ConnectionDiagnostic() ConnectionDiagnostic {
	if s == nil || s.connectionDiagnostic == nil {
		return ConnectionDiagnostic{State: "unavailable", RetryDisposition: "terminal"}
	}
	return s.connectionDiagnostic()
}

func (s *Session) LocalReport() LocalReport {
	if s == nil || s.localReport == nil {
		return LocalReport{Code: "controller_failed", Constraint: "unavailable", Reservation: "not_reserved",
			Connection: unknownConnectionFacts(), Cleanup: ConnectionCleanupStatus{Status: "pending", CoreCleanup: "pending"}, Actions: []string{}}
	}
	return s.localReport()
}

func unknownConnectionFacts() ConnectionAttemptFacts {
	return ConnectionAttemptFacts{Phase: "unknown", SpendState: "unknown", AdmissionState: "unknown",
		NetworkReady: "unknown", ApplicationPublish: "unknown", QueryAvailability: "unavailable"}
}
