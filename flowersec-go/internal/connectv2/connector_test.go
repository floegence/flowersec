package connectv2_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/runtimev2"
)

func TestAdaptiveRaceUsesOneBarrierAndCommitsOnlyAfterLosersClose(t *testing.T) {
	events := &eventLog{}
	attempts := map[string]*fakeAttempt{
		"w1": {id: "w1", readyDelay: 40 * time.Millisecond, events: events},
		"q1": {id: "q1", readyDelay: 5 * time.Millisecond, abortDelay: 15 * time.Millisecond, events: events},
		"t1": {id: "t1", readyDelay: 80 * time.Millisecond, abortDelay: 10 * time.Millisecond, events: events},
	}
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)),
		fakeFactory{attempts: attempts})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := connector.Connect(ctx)
	if err == nil {
		t.Fatal("Connect unexpectedly succeeded with non-session test carriers")
	}
	if result.Session != nil {
		t.Fatal("failed session returned a SessionV2")
	}
	if starts := events.times("start"); len(starts) != 3 || maxTime(starts).Sub(minTime(starts)) > 10*time.Millisecond {
		t.Fatalf("candidate starts did not share a barrier: %v", starts)
	}
	commit := events.first("commit:q1")
	for _, loser := range []string{"w1", "t1"} {
		closed := events.first("abort-done:" + loser)
		if closed.IsZero() || commit.Before(closed) {
			t.Fatalf("credential committed before %s was locally closed: %v", loser, events.values())
		}
		if attempts[loser].commitCount.Load() != 0 {
			t.Fatalf("loser %s committed credentials", loser)
		}
	}
	if attempts["q1"].commitCount.Load() != 1 {
		t.Fatalf("winner commit count = %d", attempts["q1"].commitCount.Load())
	}
}

func TestArtifactLeaseSpendFailureKeepsCredentialBytesAtZero(t *testing.T) {
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events}
	spendErr := errors.New("durable SPENT fsync failed")
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: validArtifact(t),
		CommitSpend: func(context.Context) error {
			events.add("spend")
			return spendErr
		},
	},
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}})
	_, err := connector.Connect(context.Background())
	if !errors.Is(err, spendErr) {
		t.Fatalf("Connect error = %v", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeCredentialCommitFailed)
	if attempt.commitCount.Load() != 0 {
		t.Fatalf("credential commit count = %d, want zero", attempt.commitCount.Load())
	}
	if connector.State() != connectv2.StateTerminated {
		t.Fatalf("state = %s, want terminated", connector.State())
	}
	if events.first("abort-done:w1").IsZero() {
		t.Fatal("winner remained writable after spend failure")
	}
}

func TestStructuredConnectErrorPreservesTunnelPath(t *testing.T) {
	artifact := validTunnelArtifact(t)
	spendErr := errors.New("tunnel durable spend failed")
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: artifact,
		CommitSpend: func(context.Context) error {
			return spendErr
		},
	},
		fakeFactory{attempts: map[string]*fakeAttempt{
			"w1": {id: "w1", events: &eventLog{}},
		}})

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, spendErr) {
		t.Fatalf("Connect error = %v", err)
	}
	assertConnectError(t, err, fserrors.PathTunnel, fserrors.StageHandshake, fserrors.CodeCredentialCommitFailed)
}

func TestArtifactLeaseSpendCompletesBeforeCredentialWrite(t *testing.T) {
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events}
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: validArtifact(t),
		CommitSpend: func(context.Context) error {
			events.add("spend")
			return nil
		},
	},
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}})
	if _, err := connector.Connect(context.Background()); err == nil {
		t.Fatal("Connect unexpectedly succeeded with non-session test carrier")
	}
	spend := events.first("spend")
	commit := events.first("commit:w1")
	if spend.IsZero() || commit.IsZero() || commit.Before(spend) {
		t.Fatalf("spend/commit order = %v", events.values())
	}
}

func TestExpiredArtifactDoesNotStartCandidatesOrSpend(t *testing.T) {
	artifact := validArtifact(t)
	now := time.Unix(2_000_000_000, 0)
	artifact = withArtifactExpiry(t, artifact, now)
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events}
	var spends atomic.Int32
	connector := connectv2.NewConnector(
		connectv2.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				spends.Add(1)
				return nil
			},
		},
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
		connectv2.WithConnectorClock(func() time.Time { return now }),
	)

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrArtifactExpired) {
		t.Fatalf("Connect error = %v, want ErrArtifactExpired", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeTimeout)
	if attempt.startCount.Load() != 0 || spends.Load() != 0 || attempt.commitCount.Load() != 0 {
		t.Fatalf("expired artifact crossed the zero-use boundary: starts=%d spends=%d commits=%d", attempt.startCount.Load(), spends.Load(), attempt.commitCount.Load())
	}
}

func TestArtifactExpiryAfterRacePreventsSpendAndCredentialWrite(t *testing.T) {
	artifact := validArtifact(t)
	now := time.Unix(2_000_000_000, 0)
	expires := now.Add(time.Minute)
	artifact = withArtifactExpiry(t, artifact, expires)
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events, readyHook: func() { now = expires }}
	var spends atomic.Int32
	connector := connectv2.NewConnector(
		connectv2.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				spends.Add(1)
				return nil
			},
		},
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
		connectv2.WithConnectorClock(func() time.Time { return now }),
	)

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrArtifactExpired) {
		t.Fatalf("Connect error = %v, want ErrArtifactExpired", err)
	}
	if spends.Load() != 0 || attempt.commitCount.Load() != 0 {
		t.Fatalf("expired artifact was spent or written: spends=%d commits=%d", spends.Load(), attempt.commitCount.Load())
	}
}

func TestArtifactExpiryDuringSpendPreventsCredentialWrite(t *testing.T) {
	artifact := validArtifact(t)
	now := time.Unix(2_000_000_000, 0)
	expires := now.Add(time.Minute)
	artifact = withArtifactExpiry(t, artifact, expires)
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", events: events}
	var spends atomic.Int32
	connector := connectv2.NewConnector(
		connectv2.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				spends.Add(1)
				now = expires
				return nil
			},
		},
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
		connectv2.WithConnectorClock(func() time.Time { return now }),
	)

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrArtifactExpired) {
		t.Fatalf("Connect error = %v, want ErrArtifactExpired", err)
	}
	if spends.Load() != 1 || attempt.commitCount.Load() != 0 {
		t.Fatalf("post-spend expiry boundary = spends %d commits %d, want 1/0", spends.Load(), attempt.commitCount.Load())
	}
}

func TestArtifactExpiryWhileCandidateIsBlockedReportsExpiry(t *testing.T) {
	base := time.Unix(2_000_000_000, 950_000_000)
	expires := base.Add(50 * time.Millisecond)
	artifact := withArtifactExpiry(t, validArtifact(t), expires)
	started := time.Now()
	events := &eventLog{}
	attempt := &fakeAttempt{
		id:         "w1",
		events:     events,
		readyBlock: make(chan struct{}),
	}
	var spends atomic.Int32
	connector := connectv2.NewConnector(
		connectv2.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				spends.Add(1)
				return nil
			},
		},
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
		connectv2.WithConnectorClock(func() time.Time { return base.Add(time.Since(started)) }),
	)

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrArtifactExpired) {
		t.Fatalf("Connect error = %v, want ErrArtifactExpired", err)
	}
	if spends.Load() != 0 || attempt.commitCount.Load() != 0 {
		t.Fatalf("expired blocked attempt crossed spend boundary: spends=%d commits=%d", spends.Load(), attempt.commitCount.Load())
	}
}

func TestSessionEstablishmentFailureClosesCarrierAndKeepsArtifactSpent(t *testing.T) {
	closed := &atomic.Bool{}
	attempt := &fakeAttempt{id: "w1", events: &eventLog{}, session: &fakeSession{kind: carrier.KindWebSocket, closed: closed}}
	factory := fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}}
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)),
		factory)
	if _, err := connector.Connect(context.Background()); err == nil {
		t.Fatal("Connect unexpectedly succeeded with a non-session test carrier")
	}
	if connector.State() != connectv2.StateTerminated {
		t.Fatalf("state = %s, want terminated", connector.State())
	}
	if !closed.Load() {
		t.Fatal("carrier remained open after session establishment failure")
	}
}

func TestConnectRejectsCarrierPathMismatchBeforeSessionHandshake(t *testing.T) {
	closed := &atomic.Bool{}
	attempts := newImmediateAttempts()
	attempts["w1"].session = &fakeSession{
		kind: carrier.KindWebSocket, path: carrier.PathTunnel, closed: closed,
	}
	connector := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		fakeFactory{attempts: attempts, capabilities: runtimev2.GoCapabilitiesForCarriers(carrier.KindWebSocket)},
	)
	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectv2.ErrInvalidFactory) && err == nil {
		t.Fatalf("Connect path mismatch error = %v, want a final carrier-boundary failure", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageAttach, fserrors.CodeAttachFailed)
	if !closed.Load() {
		t.Fatal("path-mismatched carrier session remained open")
	}
}

func TestArrayOrderDoesNotOverrideReadiness(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		artifact := validArtifact(t)
		if reverse {
			artifact.Path.Candidates[0], artifact.Path.Candidates[1] = artifact.Path.Candidates[1], artifact.Path.Candidates[0]
		}
		attempts := map[string]*fakeAttempt{
			"w1": {id: "w1", readyDelay: 30 * time.Millisecond, events: &eventLog{}},
			"q1": {id: "q1", readyDelay: time.Millisecond, events: &eventLog{}},
			"t1": {id: "t1", readyDelay: 50 * time.Millisecond, events: &eventLog{}},
		}
		_, err := connectv2.NewConnector(inMemoryLease(artifact),
			fakeFactory{attempts: attempts}).Connect(context.Background())
		if err == nil {
			t.Fatalf("Connect(reverse=%v) unexpectedly succeeded", reverse)
		}
		if events := attempts["q1"].events; events.first("ready:q1").IsZero() {
			t.Fatalf("q1 was not selected by readiness(reverse=%v)", reverse)
		}
	}
}

func TestCapabilityFilterUsesExactTuple(t *testing.T) {
	descriptor := runtimev2.CapabilityDescriptor{
		Language: "go", Runtime: "test", SchemaVersion: 2,
		Tuples: []runtimev2.CapabilityTuple{{
			Carrier: carrier.KindWebSocket, Datagrams: false, Migration: false, ReliableStreams: true,
			NetworkMode: runtimev2.NetworkDial, SessionRole: runtimev2.RoleClient, Path: carrier.PathDirect,
		}},
		Unsupported: []runtimev2.UnsupportedCapability{
			{Carrier: carrier.KindRawQUIC, Reason: "test_not_supported"},
			{Carrier: carrier.KindWebTransport, Reason: "test_not_supported"},
		},
	}
	attempts := newImmediateAttempts()
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)), fakeFactory{
		attempts: attempts, capabilities: descriptor,
	})
	_, err := connector.Connect(context.Background())
	if err == nil {
		t.Fatal("Connect unexpectedly succeeded with a non-session test carrier")
	}
	if attempts["w1"].startCount.Load() == 0 || attempts["q1"].startCount.Load() != 0 || attempts["t1"].startCount.Load() != 0 {
		t.Fatalf("capability filter started unexpected candidates: w=%d q=%d t=%d", attempts["w1"].startCount.Load(), attempts["q1"].startCount.Load(), attempts["t1"].startCount.Load())
	}
}

func TestArtifactCanOnlyBeClaimedOnceEvenWhenCommitFails(t *testing.T) {
	attempts := newImmediateAttempts()
	commitErr := errors.New("partial admission write")
	attempts["q1"].commitErr = commitErr
	attempts["t1"].commitErr = commitErr
	attempts["t1"].readyDelay = 20 * time.Millisecond
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)),
		fakeFactory{attempts: attempts, capabilities: runtimev2.GoCapabilitiesForCarriers(carrier.KindRawQUIC, carrier.KindWebTransport)})
	if _, err := connector.Connect(context.Background()); !errors.Is(err, commitErr) {
		t.Fatalf("first Connect error = %v", err)
	} else {
		assertConnectError(t, err, fserrors.PathDirect, fserrors.StageAttach, fserrors.CodeAttachFailed)
	}
	if connector.State() != connectv2.StateTerminated {
		t.Fatalf("state = %s, want terminated", connector.State())
	}
	if _, err := connector.Connect(context.Background()); !errors.Is(err, connectv2.ErrArtifactClaimed) {
		t.Fatalf("second Connect error = %v", err)
	}
}

func TestCandidateFailuresExposeStableStructuredDiagnostics(t *testing.T) {
	attempts := newImmediateAttempts()
	for id, attempt := range attempts {
		attempt.readyErr = fmt.Errorf("%s transport failed", id)
	}
	_, err := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		fakeFactory{attempts: attempts},
	).Connect(context.Background())
	structured := assertConnectError(t, err, fserrors.PathDirect, fserrors.StageConnect, fserrors.CodeDialFailed)
	if len(structured.Diagnostics) != len(attempts) {
		t.Fatalf("diagnostics = %d, want %d: %+v", len(structured.Diagnostics), len(attempts), structured.Diagnostics)
	}
	seen := make(map[string]bool, len(structured.Diagnostics))
	for _, diagnostic := range structured.Diagnostics {
		seen[diagnostic.CandidateID] = true
		if diagnostic.Stage != fserrors.StageConnect || diagnostic.Code != fserrors.CodeDialFailed {
			t.Errorf("diagnostic %s = %s/%s, want connect/dial_failed", diagnostic.CandidateID, diagnostic.Stage, diagnostic.Code)
		}
	}
	for id := range attempts {
		if !seen[id] {
			t.Errorf("missing diagnostic for candidate %s", id)
		}
	}
}

func TestConcurrentConnectRejectsSecondClaim(t *testing.T) {
	release := make(chan struct{})
	attempts := newImmediateAttempts()
	for _, attempt := range attempts {
		attempt.readyBlock = release
	}
	connector := connectv2.NewConnector(inMemoryLease(validArtifact(t)),
		fakeFactory{attempts: attempts})
	firstDone := make(chan error, 1)
	go func() {
		_, err := connector.Connect(context.Background())
		firstDone <- err
	}()
	deadline := time.Now().Add(time.Second)
	for attempts["w1"].startCount.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("first Connect did not claim artifact")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := connector.Connect(context.Background()); !errors.Is(err, connectv2.ErrArtifactClaimed) {
		t.Fatalf("concurrent Connect error = %v", err)
	}
	close(release)
	if err := <-firstDone; err == nil {
		t.Fatal("first Connect unexpectedly succeeded with non-session test carriers")
	}
}

func TestConnectDeadlineIncludesLoserCleanup(t *testing.T) {
	events := &eventLog{}
	attempts := map[string]*fakeAttempt{
		"q1": {id: "q1", events: events},
		"t1": {id: "t1", readyDelay: time.Hour, abortDelay: time.Hour, events: events},
	}
	connector := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		fakeFactory{attempts: attempts},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageAttach, fserrors.CodeTimeout)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Connect exceeded its total establishment deadline: %v", elapsed)
	}
	for _, id := range []string{"q1", "t1"} {
		if !attempts[id].locallyClosed.Load() {
			t.Fatalf("candidate %s remained locally writable: %v", id, events.values())
		}
	}
}

func TestConnectDeadlineIncludesWinnerCleanupAfterSpendFailure(t *testing.T) {
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", abortDelay: time.Hour, events: events}
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: validArtifact(t),
		CommitSpend: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	},
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	assertConnectError(t, err, fserrors.PathDirect, fserrors.StageHandshake, fserrors.CodeTimeout)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Connect exceeded its total establishment deadline: %v", elapsed)
	}
	if !attempt.locallyClosed.Load() {
		t.Fatalf("winner remained locally writable: %v", events.values())
	}
}

func assertConnectError(t *testing.T, err error, path fserrors.Path, stage fserrors.Stage, code fserrors.Code) *fserrors.Error {
	t.Helper()
	var structured *fserrors.Error
	if !errors.As(err, &structured) {
		t.Fatalf("Connect error type = %T, want *fserrors.Error: %v", err, err)
	}
	if structured.Path != path || structured.Stage != stage || structured.Code != code {
		t.Fatalf("Connect error = %s/%s/%s, want %s/%s/%s: %v", structured.Path, structured.Stage, structured.Code, path, stage, code, err)
	}
	return structured
}

func TestConnectDeadlineIncludesCandidateRace(t *testing.T) {
	events := &eventLog{}
	readyBlock := make(chan struct{})
	attempts := map[string]*fakeAttempt{
		"q1": {id: "q1", readyBlock: readyBlock, abortDelay: time.Hour, events: events},
		"t1": {id: "t1", readyBlock: readyBlock, abortDelay: time.Hour, events: events},
	}
	connector := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		fakeFactory{attempts: attempts},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("candidate race exceeded the total establishment deadline: %v", elapsed)
	}
	for _, attempt := range attempts {
		if attempt.commitCount.Load() != 0 || !events.first("ready:"+attempt.id).IsZero() {
			t.Fatalf("candidate %s crossed the credential-free ready barrier: %v", attempt.id, events.values())
		}
	}
}

func TestConnectDeadlineIncludesFSB2Admission(t *testing.T) {
	events := &eventLog{}
	attempt := &fakeAttempt{id: "w1", commitWaitForContext: true, events: events}
	connector := connectv2.NewConnector(
		inMemoryLease(validArtifact(t)),
		fakeFactory{attempts: map[string]*fakeAttempt{"w1": attempt}},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("FSB2 admission exceeded the total establishment deadline: %v", elapsed)
	}
	if connector.State() != connectv2.StateTerminated {
		t.Fatalf("state = %s, want terminated", connector.State())
	}
	if !attempt.locallyClosed.Load() {
		t.Fatalf("winner remained locally writable: %v", events.values())
	}
}

type fakeFactory struct {
	attempts     map[string]*fakeAttempt
	capabilities runtimev2.CapabilityDescriptor
}

func (factory fakeFactory) NewAttempt(candidate artifactv2.Candidate, _ artifactv2.SessionContract) (connectv2.CandidateAttempt, error) {
	attempt := factory.attempts[candidate.ID]
	if attempt == nil {
		return nil, fmt.Errorf("missing attempt %s", candidate.ID)
	}
	return attempt, nil
}

func (factory fakeFactory) Capabilities() runtimev2.CapabilityDescriptor {
	if factory.capabilities.Runtime != "" {
		return factory.capabilities
	}
	return allCapabilities()
}

type fakeAttempt struct {
	id                   string
	readyDelay           time.Duration
	abortDelay           time.Duration
	readyBlock           <-chan struct{}
	readyErr             error
	commitErr            error
	commitWaitForContext bool
	events               *eventLog
	startCount           atomic.Int32
	commitCount          atomic.Int32
	locallyClosed        atomic.Bool
	aborted              chan struct{}
	abortOnce            sync.Once
	session              carrier.Session
	readyHook            func()
}

func (attempt *fakeAttempt) Ready(ctx context.Context) (connectv2.AdmissionCommit, error) {
	attempt.startCount.Add(1)
	attempt.events.add("start:" + attempt.id)
	if attempt.readyBlock != nil {
		select {
		case <-attempt.readyBlock:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	timer := time.NewTimer(attempt.readyDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	if attempt.readyErr != nil {
		return nil, attempt.readyErr
	}
	attempt.events.add("ready:" + attempt.id)
	if attempt.readyHook != nil {
		attempt.readyHook()
	}
	return (*fakePrepared)(attempt), nil
}

func (attempt *fakeAttempt) Abort(ctx context.Context) error {
	attempt.abortOnce.Do(func() {
		attempt.events.add("abort-start:" + attempt.id)
		attempt.locallyClosed.Store(true)
		timer := time.NewTimer(attempt.abortDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		attempt.events.add("abort-done:" + attempt.id)
		if attempt.aborted != nil {
			close(attempt.aborted)
		}
	})
	return nil
}

type fakePrepared fakeAttempt

func (prepared *fakePrepared) Commit(ctx context.Context, commitSpend func(context.Context) error, fsb2 []byte) (carrier.Session, error) {
	attempt := (*fakeAttempt)(prepared)
	if len(fsb2) < artifactv2.FSB2HeaderSize || string(fsb2[:4]) != "FSB2" {
		return nil, errors.New("missing FSB2")
	}
	if commitSpend == nil {
		return nil, errors.New("missing durable spend")
	}
	if err := commitSpend(ctx); err != nil {
		return nil, err
	}
	attempt.commitCount.Add(1)
	attempt.events.add("commit:" + attempt.id)
	if attempt.commitWaitForContext {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	kind := carrier.KindRawQUIC
	if attempt.id == "w1" {
		kind = carrier.KindWebSocket
	} else if attempt.id == "t1" {
		kind = carrier.KindWebTransport
	}
	carrierSession := attempt.session
	if carrierSession == nil {
		carrierSession = &fakeSession{kind: kind, id: attempt.id, events: attempt.events, closed: &atomic.Bool{}}
	}
	return carrierSession, attempt.commitErr
}

func (prepared *fakePrepared) Close(ctx context.Context) error {
	return (*fakeAttempt)(prepared).Abort(ctx)
}

type fakeSession struct {
	kind   carrier.Kind
	path   carrier.Path
	id     string
	events *eventLog
	closed *atomic.Bool
}

func (session fakeSession) Kind() carrier.Kind { return session.kind }
func (session fakeSession) Path() carrier.Path {
	if session.path == "" {
		return carrier.PathDirect
	}
	return session.path
}
func (fakeSession) MaxIncomingStreams() uint16 { return 34 }
func (fakeSession) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, errors.New("unused")
}
func (fakeSession) AcceptStream(context.Context) (carrier.Stream, error) {
	return nil, errors.New("unused")
}
func (session fakeSession) CloseWithError(carrier.ApplicationError) error {
	if session.closed != nil {
		session.closed.Store(true)
	}
	return nil
}
func (session fakeSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	if session.closed != nil {
		session.closed.Store(true)
	}
	return nil
}
func (session fakeSession) Termination() <-chan struct{} {
	terminated := make(chan struct{})
	if session.closed != nil && session.closed.Load() {
		close(terminated)
	}
	return terminated
}
func (session fakeSession) Abort(applicationError carrier.ApplicationError) error {
	return session.CloseWithError(applicationError)
}
func (session fakeSession) Close() error {
	if session.closed != nil {
		session.closed.Store(true)
	}
	return nil
}

type event struct {
	name string
	at   time.Time
}

type eventLog struct {
	mu     sync.Mutex
	events []event
}

func (log *eventLog) add(name string) {
	log.mu.Lock()
	log.events = append(log.events, event{name: name, at: time.Now()})
	log.mu.Unlock()
}

func (log *eventLog) first(name string) time.Time {
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, event := range log.events {
		if event.name == name {
			return event.at
		}
	}
	return time.Time{}
}

func (log *eventLog) times(prefix string) []time.Time {
	log.mu.Lock()
	defer log.mu.Unlock()
	var out []time.Time
	for _, event := range log.events {
		if len(event.name) >= len(prefix) && event.name[:len(prefix)] == prefix {
			out = append(out, event.at)
		}
	}
	return out
}

func (log *eventLog) values() []event {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]event(nil), log.events...)
}

func minTime(values []time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}

func maxTime(values []time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.After(result) {
			result = value
		}
	}
	return result
}

func newImmediateAttempts() map[string]*fakeAttempt {
	events := &eventLog{}
	return map[string]*fakeAttempt{
		"w1": {id: "w1", readyDelay: 3 * time.Millisecond, events: events},
		"q1": {id: "q1", readyDelay: time.Millisecond, events: events},
		"t1": {id: "t1", readyDelay: 2 * time.Millisecond, events: events},
	}
}

func allCapabilities() runtimev2.CapabilityDescriptor { return runtimev2.GoCapabilities() }

func inMemoryLease(artifact artifactv2.Artifact) connectv2.ArtifactLease {
	return connectv2.ArtifactLease{Artifact: artifact, CommitSpend: func(context.Context) error { return nil }}
}

func validArtifact(t *testing.T) artifactv2.Artifact {
	t.Helper()
	sessionContract := artifactv2.SessionContract{
		ChannelID: "channel-1", InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: 32, AllowedSuites: []uint16{1, 2}, DefaultSuite: 1,
	}
	for index := range sessionContract.E2EEPSK {
		sessionContract.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(sessionContract)
	if err != nil {
		t.Fatalf("ComputeSessionContractHash: %v", err)
	}
	sessionContract.ContractHash = hash
	artifact := artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: sessionContract,
		Path: artifactv2.ArtifactPath{
			Kind: artifactv2.PathDirect, RendezvousGroupID: "group-1", ListenerAudience: "listener-1",
			RoutingToken: "opaque-route", Candidates: []artifactv2.Candidate{
				{ID: "w1", Carrier: artifactv2.CarrierWebSocket, URL: "wss://example.test/flowersec/v2/direct", WireProfile: "flowersec-direct/2"},
				{ID: "q1", Carrier: artifactv2.CarrierRawQUIC, URL: "quic://example.test:443", WireProfile: "flowersec-direct/2"},
				{ID: "t1", Carrier: artifactv2.CarrierWebTransport, URL: "https://example.test/flowersec/webtransport/v2/direct", WireProfile: "flowersec-direct/2"},
			},
		},
		Scoped: []artifactv2.ScopeMetadata{}, Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
	if err := artifactv2.ValidateArtifact(artifact); err != nil {
		t.Fatalf("ValidateArtifact: %v", err)
	}
	return artifact
}

func validTunnelArtifact(t *testing.T) artifactv2.Artifact {
	t.Helper()
	artifact := validArtifact(t)
	artifact.Path.Kind = artifactv2.PathTunnel
	artifact.Path.RoutingToken = ""
	artifact.Path.Role = 1
	artifact.Path.LocalEndpointInstanceID = "endpoint-local"
	artifact.Path.ExpectedPeerEndpointInstanceID = "endpoint-peer"
	artifact.Path.Token = "opaque-attach"
	artifact.Path.Candidates = []artifactv2.Candidate{
		{ID: "w1", Carrier: artifactv2.CarrierWebSocket, URL: "wss://example.test/flowersec/v2/tunnel", WireProfile: "flowersec-tunnel/2"},
		{ID: "q1", Carrier: artifactv2.CarrierRawQUIC, URL: "quic://example.test:443", WireProfile: "flowersec-tunnel/2"},
		{ID: "t1", Carrier: artifactv2.CarrierWebTransport, URL: "https://example.test/flowersec/webtransport/v2/tunnel", WireProfile: "flowersec-tunnel/2"},
	}
	if err := artifactv2.ValidateArtifact(artifact); err != nil {
		t.Fatalf("ValidateArtifact: %v", err)
	}
	return artifact
}

func withArtifactExpiry(t *testing.T, artifact artifactv2.Artifact, expiresAt time.Time) artifactv2.Artifact {
	t.Helper()
	artifact.Session.InitExpireAtUnixSeconds = expiresAt.Unix()
	hash, _, err := artifactv2.ComputeSessionContractHash(artifact.Session)
	if err != nil {
		t.Fatalf("ComputeSessionContractHash: %v", err)
	}
	artifact.Session.ContractHash = hash
	return artifact
}
