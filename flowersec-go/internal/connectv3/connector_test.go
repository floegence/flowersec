package connectv3_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/connectv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/runtimev3"
)

func TestAllEligibleCandidatesUnsupportedCreatesNoTransport(t *testing.T) {
	artifact := loadArtifact(t)
	capabilities := loadCapabilityVector(t, "typescript-browser-ca-only")
	tupleIndex := 0
	for _, tuple := range capabilities.Tuples {
		if tuple.Carrier != carrier.KindWebSocket {
			capabilities.Tuples[tupleIndex] = tuple
			tupleIndex++
		}
	}
	capabilities.Tuples = capabilities.Tuples[:tupleIndex]
	capabilities.Unsupported = append(capabilities.Unsupported, runtimev3.UnsupportedCapability{
		Carrier: carrier.KindWebSocket,
		Reason:  "browser_websocket_api_unavailable",
	})
	if _, err := runtimev3.EncodeCapabilityDescriptor(capabilities); err != nil {
		t.Fatalf("dynamic browser capability: %v", err)
	}
	factory := &failureFactory{capabilities: capabilities}
	connector := connectv3.NewConnector(
		connectv3.ArtifactLease{Artifact: artifact, CommitSpend: func(context.Context) error { return nil }},
		factory,
		connectv3.WithCandidateFilter(func(candidate artifactv3.Candidate) bool { return candidate.ID == "w-ca" }),
	)
	_, err := connector.Connect(context.Background())
	var structured *fserrors.Error
	if !errors.As(err, &structured) || structured.Code != fserrors.CodeTLSUnsupported {
		t.Fatalf("Connect error = %v, want tls_unsupported", err)
	}
	if factory.created.Load() != 0 {
		t.Fatalf("created transports = %d, want 0", factory.created.Load())
	}
	if len(structured.Diagnostics) != 1 || structured.Diagnostics[0].CandidateID != "w-ca" ||
		structured.Diagnostics[0].Code != fserrors.CodeTLSUnsupported {
		t.Fatalf("unsupported diagnostics = %+v", structured.Diagnostics)
	}
}

func loadCapabilityVector(t *testing.T, name string) runtimev3.CapabilityDescriptor {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v5/capability_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Name          string `json:"name"`
			CanonicalJSON string `json:"canonical_json"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		if vector.Name == name {
			descriptor, err := runtimev3.DecodeCapabilityDescriptor([]byte(vector.CanonicalJSON))
			if err != nil {
				t.Fatal(err)
			}
			return descriptor
		}
	}
	t.Fatalf("capability vector %q is missing", name)
	return runtimev3.CapabilityDescriptor{}
}

func TestAllExpiredPinsRemainPolicyExpiredForConnectorDiagnostics(t *testing.T) {
	artifact := loadArtifact(t)
	attemptNow := time.Unix(2_000_000_101, 0)
	// Keep the artifact initiation deadline valid while every selected pin is
	// expired at the connector's single attempt clock snapshot.
	artifact.Session.InitExpireAtUnixSeconds = attemptNow.Unix() + 60
	for index := range artifact.Path.Candidates {
		if artifact.Path.Candidates[index].ID != "q-pin" {
			continue
		}
		for pinIndex := range artifact.Path.Candidates[index].TLS.Pins {
			artifact.Path.Candidates[index].TLS.Pins[pinIndex].NotAfterUnixS = attemptNow.Unix()
		}
	}
	factory := &failureFactory{capabilities: runtimev3.GoCapabilities()}
	connector := connectv3.NewConnector(
		connectv3.ArtifactLease{Artifact: artifact, CommitSpend: func(context.Context) error { return nil }},
		factory,
		connectv3.WithConnectorClock(func() time.Time { return attemptNow }),
		connectv3.WithCandidateFilter(func(candidate artifactv3.Candidate) bool { return candidate.ID == "q-pin" }),
	)
	_, err := connector.Connect(context.Background())
	var structured *fserrors.Error
	if !errors.As(err, &structured) || structured.Code != fserrors.CodeTLSPolicyExpired {
		t.Fatalf("Connect error = %v, want tls_policy_expired", err)
	}
	if len(structured.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %+v, want one candidate diagnostic", structured.Diagnostics)
	}
	diagnostic := structured.Diagnostics[0]
	if diagnostic.Code != fserrors.CodeTLSPolicyExpired || diagnostic.Detail != "policy_expired" {
		t.Fatalf("diagnostic = %+v, want tls_policy_expired/policy_expired", diagnostic)
	}
	if factory.created.Load() != 0 {
		t.Fatalf("created transports = %d, want 0", factory.created.Load())
	}
}

func TestFailureAggregationIsIndependentOfCompletionOrder(t *testing.T) {
	orders := []map[string]time.Duration{
		{"w-ca": time.Millisecond, "q-pin": 20 * time.Millisecond},
		{"w-ca": 20 * time.Millisecond, "q-pin": time.Millisecond},
	}
	for index, delays := range orders {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			artifact := loadArtifact(t)
			factory := &failureFactory{
				capabilities: runtimev3.GoCapabilities(),
				failures: map[string]error{
					"w-ca":  x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired},
					"q-pin": errors.New("ordinary network failure"),
				},
				delays: delays,
			}
			connector := connectv3.NewConnector(
				connectv3.ArtifactLease{Artifact: artifact, CommitSpend: func(context.Context) error { return nil }},
				factory,
				connectv3.WithCandidateFilter(func(candidate artifactv3.Candidate) bool {
					return candidate.ID == "w-ca" || candidate.ID == "q-pin"
				}),
			)
			_, err := connector.Connect(context.Background())
			var structured *fserrors.Error
			if !errors.As(err, &structured) || structured.Code != fserrors.CodeTLSFailed {
				t.Fatalf("Connect error = %v, want tls_failed", err)
			}
			foundCAFailure := false
			for _, diagnostic := range structured.Diagnostics {
				if diagnostic.CandidateID == "w-ca" && diagnostic.Code == fserrors.CodeTLSFailed && diagnostic.Detail == "ca_untrusted" {
					foundCAFailure = true
				}
			}
			if !foundCAFailure {
				t.Fatalf("diagnostics = %+v, want classified CA failure", structured.Diagnostics)
			}
		})
	}
}

func TestOnlyWinnerHonorsFailedCredentialSpend(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	winner := &recordingAdmissionCommit{closed: make(chan struct{})}
	factory := &raceCandidateFactory{capabilities: runtimev3.GoCapabilities(), winnerID: "w-ca", winner: winner, loserStarted: ready}
	failedSpend := errors.New("commit spend failed")
	var spends int
	lease := connectv3.ArtifactLease{Artifact: loadArtifact(t), CommitSpend: func(ctx context.Context) error {
		spends++
		if err := ctx.Err(); err != nil {
			t.Fatalf("winner spend context already canceled: %v", err)
		}
		return failedSpend
	}}
	connector := connectv3.NewConnector(lease, factory, connectv3.WithCandidateFilter(func(candidate artifactv3.Candidate) bool { return candidate.ID == "w-ca" }))
	_, err := connector.Connect(context.Background())
	if !errors.Is(err, failedSpend) || !errors.Is(err, connectv3.ErrCredentialCommit) {
		t.Fatalf("Connect error = %v, want failed credential spend", err)
	}
	if spends != 1 || winner.fsb3Writes.Load() != 0 || !winner.closedSet.Load() || factory.aborts.Load() != 0 {
		t.Fatalf("winner: spends=%d writes=%d closed=%t loser aborts=%d", spends, winner.fsb3Writes.Load(), winner.closedSet.Load(), factory.aborts.Load())
	}
}

func TestCanceledOnlyCandidateClosesLatePreparedTransport(t *testing.T) {
	artifact := loadArtifact(t)
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		ready := make(chan connectv3.AdmissionCommit, 1)
		factory := &raceCandidateFactory{capabilities: runtimev3.GoCapabilities(), loserStarted: started, loserReady: ready}
		var spends atomic.Int32
		connector := connectv3.NewConnector(connectv3.ArtifactLease{Artifact: artifact, CommitSpend: func(context.Context) error {
			spends.Add(1)
			return nil
		}}, factory, connectv3.WithCandidateFilter(func(candidate artifactv3.Candidate) bool { return candidate.ID == "w-ca" }))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := connector.Connect(ctx)
			done <- err
		}()
		<-started
		cancel()
		synctest.Wait()
		if got := factory.aborts.Load(); got != 1 {
			t.Fatalf("Abort calls = %d, want 1", got)
		}
		select {
		case err := <-done:
			t.Fatalf("Connect returned before the canceled attempt handed back its transport: %v", err)
		default:
		}
		prepared := &recordingAdmissionCommit{closed: make(chan struct{})}
		ready <- prepared
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect error = %v, want context.Canceled", err)
		}
		if !prepared.closedSet.Load() || prepared.commitCalls.Load() != 0 || spends.Load() != 0 {
			t.Fatalf("late transport: closed=%t commits=%d spends=%d", prepared.closedSet.Load(), prepared.commitCalls.Load(), spends.Load())
		}
	})
}

func TestWinnerDoesNotWaitForStalledLoserAndClosesLatePreparedTransport(t *testing.T) {
	artifact := loadArtifact(t)
	winnerCommit := &recordingAdmissionCommit{commitErr: errors.New("admission failed"), closed: make(chan struct{})}
	loserCommit := &recordingAdmissionCommit{closed: make(chan struct{})}
	loserStarted := make(chan struct{})
	loserReady := make(chan connectv3.AdmissionCommit, 1)
	factory := &raceCandidateFactory{
		capabilities: runtimev3.GoCapabilities(),
		winnerID:     "w-ca",
		winner:       winnerCommit,
		loserStarted: loserStarted,
		loserReady:   loserReady,
	}
	connector := connectv3.NewConnector(
		connectv3.ArtifactLease{Artifact: artifact, CommitSpend: func(context.Context) error { return nil }},
		factory,
		connectv3.WithCandidateFilter(func(candidate artifactv3.Candidate) bool {
			return candidate.ID == "w-ca" || candidate.ID == "w-pin"
		}),
	)
	done := make(chan error, 1)
	go func() {
		_, err := connector.Connect(context.Background())
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Connect succeeded after the winner admission failed")
		}
	case <-time.After(time.Second):
		t.Fatal("winner admission waited for the stalled loser")
	}

	loserReady <- loserCommit
	select {
	case <-loserCommit.closed:
	case <-time.After(time.Second):
		t.Fatal("late prepared loser was not closed")
	}
	if got := loserCommit.commitCalls.Load(); got != 0 {
		t.Fatalf("late loser Commit calls = %d, want 0", got)
	}
	if got := loserCommit.spendCalls.Load(); got != 0 {
		t.Fatalf("late loser credential spend calls = %d, want 0", got)
	}
	if got := loserCommit.fsb3Writes.Load(); got != 0 {
		t.Fatalf("late loser FSB3 writes = %d, want 0", got)
	}
}

type failureFactory struct {
	capabilities runtimev3.CapabilityDescriptor
	failures     map[string]error
	delays       map[string]time.Duration
	created      atomic.Int32
}

type raceCandidateFactory struct {
	capabilities runtimev3.CapabilityDescriptor
	winnerID     string
	winner       connectv3.AdmissionCommit
	loserStarted chan struct{}
	loserReady   <-chan connectv3.AdmissionCommit
	aborts       atomic.Int32
}

func (factory *raceCandidateFactory) Capabilities() runtimev3.CapabilityDescriptor {
	return factory.capabilities
}

func (factory *raceCandidateFactory) NewAttempt(candidate artifactv3.Candidate, _ artifactv3.SessionContract, _ time.Time) (connectv3.CandidateAttempt, error) {
	if candidate.ID == factory.winnerID {
		return &raceCandidateAttempt{aborts: &factory.aborts, ready: func() connectv3.AdmissionCommit {
			<-factory.loserStarted
			return factory.winner
		}}, nil
	}
	return &raceCandidateAttempt{aborts: &factory.aborts, ready: func() connectv3.AdmissionCommit {
		close(factory.loserStarted)
		return <-factory.loserReady
	}}, nil
}

type raceCandidateAttempt struct {
	ready  func() connectv3.AdmissionCommit
	aborts *atomic.Int32
}

func (attempt *raceCandidateAttempt) Ready(context.Context) (connectv3.AdmissionCommit, error) {
	return attempt.ready(), nil
}

func (attempt *raceCandidateAttempt) Abort(context.Context) error {
	attempt.aborts.Add(1)
	return nil
}

type recordingAdmissionCommit struct {
	commitErr   error
	closed      chan struct{}
	closedSet   atomic.Bool
	commitCalls atomic.Int32
	spendCalls  atomic.Int32
	fsb3Writes  atomic.Int32
}

func (commit *recordingAdmissionCommit) Commit(ctx context.Context, spend func(context.Context) error, fsb3 []byte) (carrier.Session, error) {
	commit.commitCalls.Add(1)
	commit.spendCalls.Add(1)
	if err := spend(ctx); err != nil {
		return nil, err
	}
	if len(fsb3) != 0 {
		commit.fsb3Writes.Add(1)
	}
	return nil, commit.commitErr
}

func (commit *recordingAdmissionCommit) Close(context.Context) error {
	if commit.closedSet.CompareAndSwap(false, true) {
		close(commit.closed)
	}
	return nil
}

func (factory *failureFactory) Capabilities() runtimev3.CapabilityDescriptor {
	return factory.capabilities
}

func (factory *failureFactory) NewAttempt(candidate artifactv3.Candidate, _ artifactv3.SessionContract, _ time.Time) (connectv3.CandidateAttempt, error) {
	factory.created.Add(1)
	return &failureAttempt{err: factory.failures[candidate.ID], delay: factory.delays[candidate.ID]}, nil
}

type failureAttempt struct {
	err   error
	delay time.Duration
}

func (attempt *failureAttempt) Ready(ctx context.Context) (connectv3.AdmissionCommit, error) {
	timer := time.NewTimer(attempt.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-timer.C:
		return nil, attempt.err
	}
}

func (*failureAttempt) Abort(context.Context) error { return nil }

func loadArtifact(t *testing.T) artifactv3.Artifact {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v5/artifact_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Positive []struct {
			ArtifactJSON string `json:"artifact_json"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || len(vectors.Positive) == 0 {
		t.Fatalf("decode artifact vectors: %v", err)
	}
	artifact, err := artifactv3.DecodeArtifactJSON(bytes.NewBufferString(vectors.Positive[0].ArtifactJSON))
	if err != nil {
		t.Fatal(err)
	}
	return *artifact
}
