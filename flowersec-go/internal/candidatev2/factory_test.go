package candidatev2

import (
	"context"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/connectv2"
)

func TestCandidateAttemptLifecycleBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*fakeReadyCarrier)
		spend     func(context.Context) error
		want      error
		wantClose int32
	}{
		{name: "nil spend", spend: nil, want: connectv2.ErrInvalidArtifactLease, wantClose: 1},
		{name: "spend failure", spend: func(context.Context) error { return errSpend }, want: errSpend, wantClose: 1},
		{name: "nil exchange", configure: func(ready *fakeReadyCarrier) { ready.exchange = nil }, spend: spendOK, want: connectv2.ErrInvalidFactory, wantClose: 1},
		{name: "commit failure", configure: func(ready *fakeReadyCarrier) { ready.exchange.(*fakeAdmissionExchange).err = errExchange }, spend: spendOK, want: errExchange, wantClose: 1},
		{name: "establish failure", configure: func(ready *fakeReadyCarrier) { ready.establishErr = errEstablish }, spend: spendOK, want: errEstablish, wantClose: 1},
		{name: "nil session", configure: func(ready *fakeReadyCarrier) { ready.session = nil }, spend: spendOK, want: connectv2.ErrInvalidFactory, wantClose: 1},
		{name: "wrong carrier kind", configure: func(ready *fakeReadyCarrier) { ready.session.(*fakeCarrierSession).kind = carrier.KindRawQUIC }, spend: spendOK, want: connectv2.ErrInvalidFactory, wantClose: 1},
		{name: "wrong carrier path", configure: func(ready *fakeReadyCarrier) { ready.session.(*fakeCarrierSession).path = carrier.PathTunnel }, spend: spendOK, want: connectv2.ErrInvalidFactory, wantClose: 1},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			ready := newFakeReadyCarrier()
			if testCase.configure != nil {
				testCase.configure(ready)
			}
			attempt := newTestAttempt(t, func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (ReadyCarrier, error) {
				return ready, nil
			})
			commit, err := attempt.Ready(context.Background())
			if err != nil {
				t.Fatalf("Ready: %v", err)
			}
			_, err = commit.Commit(context.Background(), testCase.spend, []byte("FSB2"))
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Commit error = %v, want %v", err, testCase.want)
			}
			if got := ready.closeCalls.Load(); got != testCase.wantClose {
				t.Fatalf("Close calls = %d, want %d", got, testCase.wantClose)
			}
		})
	}
}

func TestCandidateAttemptRejectsDuplicateReadyAndCommit(t *testing.T) {
	ready := newFakeReadyCarrier()
	attempt := newTestAttempt(t, func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (ReadyCarrier, error) {
		return ready, nil
	})
	commit, err := attempt.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attempt.Ready(context.Background()); !errors.Is(err, ErrAttemptAlreadyUsed) {
		t.Fatalf("duplicate Ready error = %v", err)
	}
	if _, err := commit.Commit(context.Background(), spendOK, []byte("FSB2")); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if _, err := commit.Commit(context.Background(), spendOK, []byte("FSB2")); !errors.Is(err, ErrCommitAlreadyUsed) {
		t.Fatalf("duplicate Commit error = %v", err)
	}
}

func TestCandidateAttemptNilReadyFailsClosed(t *testing.T) {
	attempt := newTestAttempt(t, func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (ReadyCarrier, error) {
		return nil, nil
	})
	if _, err := attempt.Ready(context.Background()); !errors.Is(err, connectv2.ErrInvalidFactory) {
		t.Fatalf("Ready error = %v", err)
	}
}

func TestCandidateAttemptAbortBeforeReadyPreventsDial(t *testing.T) {
	var dialed atomic.Bool
	attempt := newTestAttempt(t, func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (ReadyCarrier, error) {
		dialed.Store(true)
		return newFakeReadyCarrier(), nil
	})
	if err := attempt.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := attempt.Ready(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Ready error = %v", err)
	}
	if dialed.Load() {
		t.Fatal("dial ran after Abort")
	}
}

func TestCandidateAttemptAbortDuringDialPrefersCancellationAndClosesLateCarrierOnce(t *testing.T) {
	ready := newFakeReadyCarrier()
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	attempt := newTestAttempt(t, func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (ReadyCarrier, error) {
		close(dialStarted)
		<-releaseDial
		return ready, nil
	})
	readyErr := make(chan error, 1)
	go func() {
		_, err := attempt.Ready(context.Background())
		readyErr <- err
	}()
	<-dialStarted
	abortErr := make(chan error, 1)
	go func() { abortErr <- attempt.Abort(context.Background()) }()
	waitForAttemptAbort(t, attempt)
	close(releaseDial)
	if err := <-readyErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("Ready error = %v", err)
	}
	if err := <-abortErr; err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := attempt.Abort(context.Background()); err != nil {
		t.Fatalf("duplicate Abort: %v", err)
	}
	if got := ready.closeCalls.Load(); got != 1 {
		t.Fatalf("late carrier Close calls = %d, want 1", got)
	}
}

func waitForAttemptAbort(t *testing.T, candidate connectv2.CandidateAttempt) {
	t.Helper()
	attempt := candidate.(*candidateAttempt)
	deadline := time.Now().Add(time.Second)
	for {
		attempt.mu.Lock()
		aborted := attempt.aborted
		attempt.mu.Unlock()
		if aborted {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Abort did not publish state")
		}
		runtime.Gosched()
	}
}

func TestCandidateAttemptAbortDuringDialPrefersCancellationOverDialError(t *testing.T) {
	dialStarted := make(chan struct{})
	attempt := newTestAttempt(t, func(ctx context.Context, _ artifactv2.Candidate, _ artifactv2.SessionContract) (ReadyCarrier, error) {
		close(dialStarted)
		<-ctx.Done()
		return nil, errDial
	})
	readyErr := make(chan error, 1)
	go func() {
		_, err := attempt.Ready(context.Background())
		readyErr <- err
	}()
	<-dialStarted
	if err := attempt.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-readyErr; !errors.Is(err, context.Canceled) || errors.Is(err, errDial) {
		t.Fatalf("Ready error = %v, want cancellation priority", err)
	}
}

func TestCandidateAttemptAbortAfterReadyClosesExactlyOnce(t *testing.T) {
	ready := newFakeReadyCarrier()
	attempt := newTestAttempt(t, func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (ReadyCarrier, error) {
		return ready, nil
	})
	commit, err := attempt.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_ = commit.Close(context.Background())
		}()
	}
	wait.Wait()
	if got := ready.closeCalls.Load(); got != 1 {
		t.Fatalf("Close calls = %d, want 1", got)
	}
}

func TestCandidateAttemptAbortWaitHonorsCallerContext(t *testing.T) {
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	attempt := newTestAttempt(t, func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (ReadyCarrier, error) {
		close(dialStarted)
		<-releaseDial
		return nil, errDial
	})
	go func() { _, _ = attempt.Ready(context.Background()) }()
	<-dialStarted
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := attempt.Abort(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Abort error = %v", err)
	}
	close(releaseDial)
}

var (
	errDial      = errors.New("dial failed")
	errSpend     = errors.New("spend failed")
	errExchange  = errors.New("exchange failed")
	errEstablish = errors.New("establish failed")
)

func spendOK(context.Context) error { return nil }

func newTestAttempt(t *testing.T, dial Dial) connectv2.CandidateAttempt {
	t.Helper()
	factory, err := NewFactory(map[artifactv2.Carrier]Dial{artifactv2.CarrierWebSocket: dial})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := factory.NewAttempt(artifactv2.Candidate{Carrier: artifactv2.CarrierWebSocket, WireProfile: "flowersec-direct/2"}, artifactv2.SessionContract{})
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

type fakeReadyCarrier struct {
	exchange     admissionv2.ClientExchange
	session      carrier.Session
	establishErr error
	closeErr     error
	closeCalls   atomic.Int32
}

func newFakeReadyCarrier() *fakeReadyCarrier {
	return &fakeReadyCarrier{
		exchange: &fakeAdmissionExchange{},
		session:  &fakeCarrierSession{kind: carrier.KindWebSocket, path: carrier.PathDirect, terminated: make(chan struct{})},
	}
}

func (ready *fakeReadyCarrier) Admission() admissionv2.ClientExchange { return ready.exchange }
func (ready *fakeReadyCarrier) Establish() (carrier.Session, error) {
	return ready.session, ready.establishErr
}
func (ready *fakeReadyCarrier) Close(context.Context) error {
	ready.closeCalls.Add(1)
	return ready.closeErr
}

type fakeAdmissionExchange struct {
	err   error
	calls atomic.Int32
}

func (exchange *fakeAdmissionExchange) Commit(context.Context, []byte) error {
	exchange.calls.Add(1)
	return exchange.err
}

type fakeCarrierSession struct {
	kind       carrier.Kind
	path       carrier.Path
	terminated chan struct{}
}

func (session *fakeCarrierSession) Kind() carrier.Kind { return session.kind }
func (session *fakeCarrierSession) Path() carrier.Path { return session.path }
func (*fakeCarrierSession) MaxIncomingStreams() uint16 { return 1 }
func (*fakeCarrierSession) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, io.ErrClosedPipe
}
func (*fakeCarrierSession) AcceptStream(context.Context) (carrier.Stream, error) {
	return nil, io.ErrClosedPipe
}
func (session *fakeCarrierSession) Termination() <-chan struct{} { return session.terminated }
func (*fakeCarrierSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	return nil
}
func (*fakeCarrierSession) CloseWithError(carrier.ApplicationError) error { return nil }
func (*fakeCarrierSession) Abort(carrier.ApplicationError) error          { return nil }
func (*fakeCarrierSession) Close() error                                  { return nil }

var _ ReadyCarrier = (*fakeReadyCarrier)(nil)
var _ carrier.Session = (*fakeCarrierSession)(nil)
