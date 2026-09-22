package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type acceptedPipe struct {
	net.Conn
	closes      atomic.Uint32
	winner      protocolv4.PoolMember
	environment resourcev4.Reference
}

func (p *acceptedPipe) CheckEnvironment(environment resourcev4.Reference) error {
	return p.environment.CheckSameEnvironment(environment)
}

func (p *acceptedPipe) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	// The pipe substitutes only transport I/O in the authenticated fixture.
	// Real TLS observation is covered by concrete WebSocket integration tests.
	g, _ := protocolv4.ConnectionAssurance("native_websocket_tls13")
	return g, nil
}

func (p *acceptedPipe) CheckAcceptedRoute(artifact *protocolv4.SignedMap, index uint64, policy protocolv4.HelloPolicy) error {
	if err := artifact.CheckDirectListenerCandidate(index); err != nil {
		return err
	}
	_, route, err := artifact.CopyCandidateRoute(index, make([]byte, 16384))
	if err != nil {
		return err
	}
	id, _ := artifact.Field("candidates").Index(int(index)).Named("Candidate", "candidate_id").ByteString()
	if p.winner != (protocolv4.PoolMember{Index: index, CandidateID: [16]byte(id), RouteDigest: route}) || policy.BindingMode != 1 {
		return protocolv4.CBORFailure("accepted_listener_binding")
	}
	return nil
}

// This synthetic lifecycle provider never reaches route negotiation. Real
// admission fixtures above explicitly bind their expected original candidate.
type acceptedLifecycleProvider struct{ *preparedTestProvider }

func (*acceptedLifecycleProvider) CheckAcceptedRoute(*protocolv4.SignedMap, uint64, protocolv4.HelloPolicy) error {
	return protocolv4.CBORFailure("accepted_listener_binding")
}

func (p *acceptedPipe) Close() error                      { p.closes.Add(1); return p.Conn.Close() }
func (p *acceptedPipe) WaitCleanup(context.Context) error { return nil }
func (p *acceptedPipe) Retire() error                     { return nil }

func acceptedTestConfig(f *admissionIntegrationFixture) AcceptedEntranceConfig {
	c := f.config.Initial
	c.Role = protocolv4.ServerToClient
	return AcceptedEntranceConfig{Initial: c, RuntimeBytes: 8192, InitialRuntimeBytes: 8192, CarrierRuntimeBytes: 8192}
}
func cleanupAccepted(t *testing.T, e *AcceptedEntrance) {
	t.Helper()
	t.Cleanup(func() {
		e.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := e.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := e.Retire(); err != nil {
			t.Error(err)
		}
	})
}

func TestAcceptedEntranceReservesOnlyPreauthAndKeepsPhysicalTail(t *testing.T) {
	f := admissionIntegration(t, context.Background())
	c := acceptedTestConfig(f)
	provider := &acceptedLifecycleProvider{&preparedTestProvider{environment: f.environment, closeEntered: make(chan struct{}), closeRelease: make(chan struct{})}}
	pool, err := f.root.Account(resourcev4.AccountKey{Kind: resourcev4.PoolAccount, ID: [16]byte{80}}, f.root.Snapshot().Limit)
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot()
	want, err := AcceptedEntranceRequirements(c)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewAcceptedMessages(context.Background(), c, provider, f.root, admissionResourceKey(f.owner, 211), f.environment, pool)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAccepted(t, e)
	after := f.root.Snapshot()
	expected, _ := before.Charged.Add(want)
	if after.Charged != expected || after.Charged[resourcev4.Sessions] != before.Charged[resourcev4.Sessions] {
		t.Fatal("preauth charge omitted, duplicated or claimed a Session", after.Charged)
	}
	e.Close()
	select {
	case <-provider.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("Initial did not close provider")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := e.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("provider tail ignored", err)
	}
	if f.root.Snapshot().Charged != after.Charged {
		t.Fatal("preauth released before provider exit")
	}
	close(provider.closeRelease)
	if err := e.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.root.Snapshot().Charged != after.Charged {
		t.Fatal("original backing released before retirement")
	}
	if err := e.Retire(); err != nil {
		t.Fatal(err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("preauth retirement leaked charge", f.root.Snapshot(), before)
	}
	if provider.closes.Load() != 1 {
		t.Fatal("duplicate physical Close")
	}
}

func TestAcceptedEntranceRefusalPreservesProvider(t *testing.T) {
	f := admissionIntegration(t, context.Background())
	c := acceptedTestConfig(f)
	limit := f.root.Snapshot().Limit
	limit[resourcev4.SDKBytes] = 1
	pool, err := f.root.Account(resourcev4.AccountKey{Kind: resourcev4.PoolAccount, ID: [16]byte{80}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot()
	provider := &acceptedLifecycleProvider{&preparedTestProvider{environment: f.environment}}
	e, err := NewAcceptedMessages(context.Background(), c, provider, f.root, admissionResourceKey(f.owner, 211), f.environment, pool)
	if e != nil || !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("undersized preauth admitted", err)
	}
	if f.root.Snapshot() != before || provider.closes.Load() != 0 || provider.reads.Load() != 0 || provider.writes.Load() != 0 {
		t.Fatal("failed construction consumed provider or resources")
	}
}

func acceptedVerifiedFlight(t *testing.T, prepare ...func(*sessionAdmissionTrustFixture)) (*admissionIntegrationFixture, *AcceptedEntrance, *InitialExchange, *protocolv4.SignedMap) {
	t.Helper()
	f := admissionIntegration(t, context.Background())
	for _, mutate := range prepare {
		mutate(f.trust)
	}
	c := acceptedTestConfig(f)
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	e, err := NewAcceptedStream(context.Background(), c, &acceptedPipe{Conn: right, winner: f.trust.candidate, environment: f.environment}, f.root, admissionResourceKey(f.owner, 211), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAccepted(t, e)
	clientConfig := f.config.Initial
	clientConfig.Authorization, err = protocolv4.NewEndpointAuthorization(f.trust.subscriptions[0], f.trust.authority)
	if err != nil {
		t.Fatal(err)
	}
	charge, err := InitialCharge(clientConfig.Limits)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.Reservation, err = f.root.Reserve(admissionResourceKey(f.owner, 212), charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clientConfig.Reservation.Release)
	client, err := NewInitialStream(context.Background(), clientConfig, left)
	if err != nil {
		t.Fatal(err)
	}
	cleanupInitial(t, client)
	workspace := func() *protocolv4.HelloWorkspace {
		w, err := protocolv4.NewHelloWorkspace(protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	hello := InitialHello{Artifact: f.trust.artifact, Index: 0, Attempt: f.trust.attempt, Workspace: workspace(), Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}
	clientDone := make(chan error, 1)
	go func() { _, err := client.NegotiateClient(hello); clientDone <- err }()
	input := make([]byte, 16384)
	n, err := e.ReadClientHello(input)
	if err != nil {
		t.Fatal(err)
	}
	hello.Workspace = workspace()
	if _, err = e.Negotiate(hello); err != nil {
		t.Fatal(err)
	}
	if err = <-clientDone; err != nil {
		t.Fatal(err)
	}
	copyBuffer := make([]byte, 16384)
	count, err := e.initial.CopyClientHello(copyBuffer)
	if err != nil || !bytes.Equal(input[:n], copyBuffer[:count]) {
		t.Fatal("negotiation replaced original Hello", err)
	}
	clientCodec, err := protocolv4.NewSignedMapCodec("FSB4", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	serverCodec, err := protocolv4.NewSignedMapCodec("FSB4", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		signed, _, err := client.SendAdmission(f.trust.activation, f.trust.proof, f.trust.certificates[0], clientCodec, f.trust.signers[0], func() error {
			_, err := clientConfig.Authorization.(*protocolv4.EndpointAuthorization).CheckAdmission()
			return err
		})
		if signed != nil {
			signed.Release()
		}
		clientDone <- err
	}()
	var fsb *protocolv4.SignedMap
	err = e.ReceiveAdmission(func(wire []byte) error {
		var verifyErr error
		fsb, verifyErr = serverCodec.Verify(wire, [32]byte(f.trust.signers[0].PublicKey()), protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
		return verifyErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = <-clientDone; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fsb.Release)
	return f, e, client, fsb
}

func TestAcceptedEntranceAuthenticatesFSBBeforeAnySessionOrFSA(t *testing.T) {
	f, e, _, fsb := acceptedVerifiedFlight(t)
	if _, err := e.initial.hello.MatchFSB(f.trust.activation, fsb, f.trust.certificates[0]); err != nil {
		t.Fatal(err)
	}
	if f.root.Snapshot().Charged[resourcev4.Sessions] != 0 {
		t.Fatal("accepted preauth acquired Session capacity")
	}
	builds := 0
	result, err := e.initial.Send(protocolv4.FrameAdmissionResult, func([]byte) (int, error) { builds++; return 0, nil })
	if !errors.Is(err, ErrAdmissionRejected) || result.Started || builds != 0 {
		t.Fatal("preauth admitted FSA signing/publication", result, err)
	}
	if _, err := e.initial.Authenticate(cryptov4.HandshakeConfig{}, cryptov4.Config{}, func(*cryptov4.Engine) error { t.Fatal("preauth started Noise"); return nil }); err == nil {
		t.Fatal("preauth authenticated")
	}
}
