package sessionv4

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

func TestConnectionAdmissionFactsFollowFSB4AndFSA4OwnerCutpoints(t *testing.T) {
	host := &EnvironmentSession{ready: make(chan struct{}), published: make(chan struct{})}
	owner := &SessionEstablishment{sessionEstablishment: &sessionEstablishment{host: host}}

	before := host.ConnectionAttemptFacts()
	if before.AdmissionState != "unknown" || before.NetworkReady != "unknown" {
		t.Fatalf("unobserved admission must remain unknown: %+v", before)
	}

	owner.recordAdmissionState("in_flight")
	inFlight := host.ConnectionAttemptFacts()
	if inFlight.AdmissionState != "in_flight" || inFlight.NetworkReady != "not_started" {
		t.Fatalf("FSB4 publication must record only in-flight admission: %+v", inFlight)
	}
	failed := &EnvironmentSession{ready: make(chan struct{}), published: make(chan struct{}), closed: true, result: cryptov4.ErrClosed, admissionState: "in_flight"}
	if facts := failed.ConnectionAttemptFacts(); facts.AdmissionState != "unknown" {
		t.Fatalf("terminal failure must not retain an in-flight projection: %+v", facts)
	}

	owner.recordAdmissionState("admitted")
	admitted := host.ConnectionAttemptFacts()
	if admitted.AdmissionState != "admitted" || admitted.NetworkReady != "not_started" || admitted.Phase != "admitted_not_ready" || admitted.SpendState != "spent" || admitted.Spent == nil || !*admitted.Spent {
		t.Fatalf("verified FSA4 must precede READY evidence: %+v", admitted)
	}

	host.diagnosticNetworkReady = true
	close(host.ready)
	ready := host.ConnectionAttemptFacts()
	if ready.AdmissionState != "admitted" || ready.NetworkReady != "ready" || ready.Phase != "ready" {
		t.Fatalf("original READY owner must publish readiness: %+v", ready)
	}
	close(host.published)
	published := host.ConnectionAttemptFacts()
	if published.ApplicationPublish != "published" {
		t.Fatalf("application publication must use its original owner: %+v", published)
	}
}

func TestConnectionFactsRetainPositiveSpendAndPublicationAfterCleanup(t *testing.T) {
	host := &EnvironmentSession{ready: make(chan struct{}), published: make(chan struct{}), admissionState: "admitted", diagnosticSourceProfile: "live_authority"}
	before := host.ConnectionAttemptFacts()
	if before.SpendState != "spent" || before.Spent == nil || !*before.Spent || before.NetworkReady != "not_started" {
		t.Fatal("verified admission discarded original live spend", before)
	}
	host.diagnosticNetworkReady = true
	close(host.ready)
	close(host.published)
	host.closed, host.cleaned, host.result = true, true, cryptov4.ErrClosed
	after := host.ConnectionAttemptFacts()
	if after.SpendState != "spent" || after.Phase != "ready" || after.NetworkReady != "ready" || after.ApplicationPublish != "published" {
		t.Fatal("cleanup erased original authenticated facts", after)
	}
	after.Spent = nil
	if original := host.ConnectionAttemptFacts(); original.Spent == nil || !*original.Spent {
		t.Fatal("detached projection mutated original facts", original)
	}
}

func TestFailedApplicationPublicationDoesNotEraseReadyOrSpentFacts(t *testing.T) {
	host := &EnvironmentSession{ready: make(chan struct{}), published: make(chan struct{}), admissionState: "admitted"}
	host.diagnosticNetworkReady = true
	close(host.ready)
	host.closed, host.result = true, cryptov4.ErrConfiguration
	facts := host.ConnectionAttemptFacts()
	if facts.ApplicationPublish != "failed" || facts.SpendState != "spent" || facts.NetworkReady != "ready" {
		t.Fatal("publication failure rewrote admission or spend", facts)
	}
}

func TestControllerDiagnosticRetainsDetachedFactsAfterCandidateRetirement(t *testing.T) {
	spent := true
	c := &ConnectionController{closed: true, cleaned: true, serial: 3, lastError: cryptov4.ErrConfiguration, hasLastDiagnostic: true,
		lastDiagnostic: ConnectionDiagnostic{Connection: &ConnectionAttemptFacts{Phase: "ready", Spent: &spent, SpendState: "spent",
			AdmissionState: "admitted", NetworkReady: "ready", ApplicationPublish: "failed", QueryAvailability: "unavailable"}}}
	observed := c.ConnectionDiagnostic()
	if observed.State != "closed" || observed.Attempt != 3 || observed.Connection == nil || observed.Connection.SpendState != "spent" || observed.Cleanup.Status != "complete" {
		t.Fatal("Controller retirement erased candidate facts", observed)
	}
	*observed.Connection.Spent = false
	observed.Connection.ApplicationPublish = "published"
	repeated := c.ConnectionDiagnostic()
	if repeated.Connection.Spent == nil || !*repeated.Connection.Spent || repeated.Connection.ApplicationPublish != "failed" {
		t.Fatal("public diagnostic mutated retained facts", repeated)
	}
}

func TestControllerPublicationFactsFollowCurrentSwitchAfterSessionDelivery(t *testing.T) {
	host := &EnvironmentSession{ready: make(chan struct{}), published: make(chan struct{}), admissionState: "admitted", controllerManaged: true}
	host.diagnosticNetworkReady = true
	close(host.ready)
	close(host.published)
	before := host.ConnectionAttemptFacts()
	if before.ApplicationPublish != "not_started" || before.NetworkReady != "ready" || before.SpendState != "spent" {
		t.Fatal("candidate delivery was confused with Controller publication", before)
	}
	host.mu.Lock()
	host.controllerApplicationPublished = true
	host.mu.Unlock()
	after := host.ConnectionAttemptFacts()
	if after.ApplicationPublish != "published" {
		t.Fatal("current switch did not publish original facts", after)
	}
}

func TestFailedEstablishmentWakeDoesNotInventAuthenticatedReadiness(t *testing.T) {
	host := &EnvironmentSession{ready: make(chan struct{}), published: make(chan struct{}),
		closed: true, result: cryptov4.ErrConfiguration, admissionState: "in_flight"}
	close(host.ready)
	facts := host.ConnectionAttemptFacts()
	if facts.NetworkReady == "ready" || facts.AdmissionState == "admitted" || facts.SpendState == "spent" || facts.Spent != nil {
		t.Fatal("failed readiness wake invented successful authentication or spend", facts)
	}
}

func TestSessionDiagnosticKeepsOriginalControllerAttemptIdentity(t *testing.T) {
	host := &EnvironmentSession{ready: make(chan struct{}), published: make(chan struct{}),
		closed: true, cleaned: true, controllerDiagnosticAttempt: 2}
	if got := host.ConnectionDiagnostic().Attempt; got != 2 {
		t.Fatal("lost original attempt identity", got)
	}
}

func TestControllerCandidateLessFailureNeverBorrowsPredecessorFacts(t *testing.T) {
	previous := &EnvironmentSession{ready: make(chan struct{}), published: make(chan struct{}),
		admissionState: "admitted", diagnosticNetworkReady: true, controllerManaged: true,
		controllerApplicationPublished: true, controllerDiagnosticAttempt: 1, closed: true, cleaned: true}
	close(previous.ready)
	close(previous.published)
	controller := &ConnectionController{closed: true, cleaned: true, current: previous, serial: 2,
		lastError: cryptov4.ErrConfiguration, hasLastDiagnostic: true, lastDiagnostic: unknownAttemptDiagnostic(2),
		attempt: &controllerAttempt{serial: 2, finished: true}}
	for _, retiring := range []bool{false, true} {
		if retiring {
			controller.attempt = nil
		}
		observed := controller.ConnectionDiagnostic()
		if observed.Attempt != 2 || observed.Connection == nil || observed.Connection.Spent != nil ||
			observed.Connection.SpendState != "unknown" || observed.Connection.NetworkReady != "unknown" ||
			observed.Connection.ApplicationPublish != "unknown" {
			t.Fatal("candidate-less replacement failure borrowed predecessor facts", retiring, observed)
		}
	}
}
