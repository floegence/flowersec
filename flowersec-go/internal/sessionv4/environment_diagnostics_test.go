package sessionv4

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// A provider can return arbitrary error implementations, including values that
// are not comparable. Diagnostics must neither call them nor retain their data.
type hostileDiagnosticError []byte

func (hostileDiagnosticError) Error() string { panic("application Error called") }
func (hostileDiagnosticError) Is(error) bool { panic("application Is called") }
func (hostileDiagnosticError) Unwrap() error { panic("application Unwrap called") }

func TestApplicationDiagnosticRetainsOnlyFiniteFailureThroughOriginalTails(t *testing.T) {
	for _, cause := range []error{hostileDiagnosticError("private application detail"), context.Canceled, context.DeadlineExceeded} {
		op := &DiagnosticOperation{applicationReferences: 2}
		finishApplicationDiagnosticError(op, cause)
		want, _ := diagnosticFailure(cause)
		if op.applicationReferences != 1 || !op.applicationFailed || op.applicationFailure != want {
			t.Fatal("original physical tail lost its finite outcome")
		}
		finishApplicationDiagnostic(op)
		if op.applicationReferences != 0 || op.applicationFailed || retainApplicationDiagnostic(op) {
			t.Fatal("completed operation retained or reacquired its diagnostic")
		}
	}
}

func TestEnvironmentDiagnosticErrorProjectionDoesNotCallApplication(t *testing.T) {
	loop := &net.OpError{}
	loop.Err = loop
	for _, cause := range []error{hostileDiagnosticError("private provider detail"), loop, (*net.OpError)(nil), (*url.Error)(nil), (*tls.CertificateVerificationError)(nil)} {
		code, metric := diagnosticFailure(cause)
		if code != diagnosticv4.CodeOther || metric != diagnosticv4.MetricOther {
			t.Fatal("unknown error acquired a diagnostic classification")
		}
	}
	for _, tc := range []struct {
		cause  error
		code   diagnosticv4.Code
		metric diagnosticv4.Metric
	}{
		{&url.Error{Op: "private", URL: "private", Err: &net.OpError{Err: tlspolicy.ErrCertificate}}, diagnosticv4.CodeTLSRejected, diagnosticv4.MetricTLSRejection},
		{&tls.CertificateVerificationError{Err: hostileDiagnosticError("private")}, diagnosticv4.CodeTLSRejected, diagnosticv4.MetricTLSRejection},
		{protocolv4.CBORFailure("admission_identity_binding"), diagnosticv4.CodeIdentityRejected, diagnosticv4.MetricIdentityRejection},
		{ledgerv4.ErrUnknown, diagnosticv4.CodeSpendUnknown, diagnosticv4.MetricSpendUnknown},
		{ledgerv4.ErrStorageUnavailable, diagnosticv4.CodeStoreUnavailable, diagnosticv4.MetricStoreFailure},
		{ledgerv4.ErrConflict, diagnosticv4.CodeReservationConflict, diagnosticv4.MetricReservationConflict},
	} {
		code, metric := diagnosticFailure(tc.cause)
		if code != tc.code || metric != tc.metric {
			t.Fatal("known finite diagnostic classification lost", code, metric)
		}
	}
}

func TestEnvironmentDiagnosticClosureCountsOriginalTransition(t *testing.T) {
	e := &Environment{}
	s := newEnvironmentSession(e, 0, context.Background())
	s.beginDiagnostics()
	var calls sync.WaitGroup
	for range 32 {
		calls.Go(func() { s.closeWith(hostileDiagnosticError("private")) })
	}
	calls.Wait()
	if got := e.DiagnosticCounts(diagnosticv4.MetricConnectionFailure); got.Total != 1 || got.Code[diagnosticv4.CodeOther] != 1 {
		t.Fatal("concurrent closure counted repeatedly", got)
	}
	// A successful delivery's explicit close does not inflate failures.
	s = newEnvironmentSession(e, 1, context.Background())
	s.beginDiagnostics()
	s.delivered = true
	s.Close()
	if e.DiagnosticCounts(diagnosticv4.MetricConnectionAttempt).Total != 2 || e.DiagnosticCounts(diagnosticv4.MetricConnectionFailure).Total != 1 {
		t.Fatal("normal close was a connection failure")
	}
	// A completed original cleanup cannot be turned into a timeout by a late
	// observer, and caller cancellation is not reported as cleanup expiry.
	s.observeCleanupTimeout(context.Canceled)
	s.cleaned, s.environment = true, nil
	s.observeCleanupTimeout(context.DeadlineExceeded)
	if e.DiagnosticCounts(diagnosticv4.MetricCleanupTimeout).Total != 0 {
		t.Fatal("completed cleanup counted as timeout")
	}
	s.closeWith(cryptov4.ErrClosed)
}

func TestEnvironmentDiagnosticConsumerSaturationPreservesCredit(t *testing.T) {
	pool, err := testReceivePool(t, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var counts diagnosticv4.Counters
	pool.diagnostics = &counts
	flow, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 8, TerminalTuple{}, 8)
	if err != nil {
		t.Fatal(err)
	}
	wire := newFlowTransport(t)
	if err = wire.data(t, flow, 0, false, "12345678"); err != nil {
		t.Fatal(err)
	}
	if counts.Snapshot(diagnosticv4.MetricSlowConsumer).Total != 1 || pool.Outstanding() != 8 {
		t.Fatal("original unread saturation missing or promise changed")
	}
	var output [8]byte
	if n, _, err := flow.TryRead(output[:]); err != nil || n != 8 || string(output[:]) != "12345678" {
		t.Fatal("observation changed payload delivery", n, err)
	}
	if err = flow.Grant(16); err != nil {
		t.Fatal(err)
	}
	if err = wire.data(t, flow, 8, false, "abcdefgh"); err != nil {
		t.Fatal(err)
	}
	if counts.Snapshot(diagnosticv4.MetricSlowConsumer).Total != 1 || pool.Outstanding() != 8 {
		t.Fatal("same receive direction counted again or lost its promise")
	}
	if n, _, err := flow.TryRead(output[:]); err != nil || n != 8 {
		t.Fatal(n, err)
	}
	if err = wire.data(t, flow, 16, true, ""); err != nil {
		t.Fatal(err)
	}
	flow.Fence()
	if err = flow.Cleanup(); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if pool.diagnostics != nil {
		t.Fatal("closed receive pool retained the bank")
	}
}

func TestEnvironmentSessionAutomaticallyEmitsConnectionDiagnostics(t *testing.T) {
	events := make(chan diagnosticv4.Event, 4)
	sampling, release := make(chan struct{}), make(chan struct{})
	var sampleOnce, releaseOnce sync.Once
	f := newDiagnosticFixture(t, DiagnosticSinkConfig{}, func(_ context.Context, event diagnosticv4.Event) {
		events <- event
	}, func(uint16) bool {
		sampleOnce.Do(func() { close(sampling); <-release })
		return true
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	// Begin and Emit intentionally drop on diagnostic lock contention. Hold
	// the real pump at its sampling boundary, outside that lock, while testing
	// both automatic transitions; the seed also exercises actual delivery.
	seed := f.begin(t)
	diagnosticEmit(t, seed, diagnosticv4.Fields{State: diagnosticv4.StateStarting, Phase: diagnosticv4.PhasePrepare, Code: diagnosticv4.CodeOK})
	diagnosticReceive(t, sampling)
	dropsBefore := f.sink.Counters(diagnosticv4.MetricDiagnosticDrop).Total
	e := &Environment{diagnosticSink: f.sink}
	s := newEnvironmentSession(e, 0, context.Background())
	s.beginDiagnostics()
	s.closeWith(context.Canceled)
	releaseOnce.Do(func() { close(release) })
	starting, failed := 0, 0
	for range 3 {
		fields := diagnosticReceive(t, events).Fields()
		switch {
		case fields.State == diagnosticv4.StateStarting && fields.Code == diagnosticv4.CodeOK:
			starting++
		case fields.State == diagnosticv4.StateFailed && fields.Code == diagnosticv4.CodeCancelled:
			failed++
		default:
			t.Fatal("unexpected automatic diagnostic fields", fields)
		}
	}
	if starting != 2 || failed != 1 || f.sink.Counters(diagnosticv4.MetricDiagnosticDrop).Total != dropsBefore {
		t.Fatal("automatic diagnostic transitions were lost", starting, failed)
	}
	if got := e.DiagnosticCounts(diagnosticv4.MetricConnectionAttempt).Total; got != 1 {
		t.Fatal("automatic connection attempt aggregate missing", got)
	}
	if got := e.DiagnosticCounts(diagnosticv4.MetricConnectionFailure).Total; got != 1 {
		t.Fatal("automatic connection failure aggregate missing", got)
	}
	if s.diagnosticOperation == nil {
		t.Fatal("environment session did not retain the sink operation")
	}
	s.diagnosticOperation.Close()
	s.diagnosticOperation = nil
}
