package interopharness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// These lookup tests use complete independently signed original material. A
// successful lookup is not counted as admission, a spend, or a Session.
func registryHello(t *testing.T, h *sessionv4.PublicQUICTestHarness) []byte {
	t.Helper()
	decoder, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := decoder.DecodeMap(h.Lease.Artifact, "Artifact", protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Release()
	candidate := artifact.Root().Named("Artifact", "candidates").Index(0)
	candidateID, ok := candidate.Named("Candidate", "candidate_id").ByteString()
	if !ok {
		t.Fatal("signed candidate identity is absent")
	}
	nonce, ok := artifact.Root().Named("Artifact", "session_nonce").ByteString()
	if !ok {
		t.Fatal("signed client nonce is absent")
	}
	protocol, err := protocolv4.ConstantField("ClientHello", "protocol_id")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := protocolv4.ConstantField("ClientHello", "profile_revision")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocolv4.EncodeMap(make([]byte, 16384), "ClientHello", []protocolv4.Field{
		protocol, revision, {Name: "crypto_profile_id", Kind: protocolv4.TextString, Text: h.Admission[0].Initial.Profile},
		{Name: "artifact_digest", Kind: protocolv4.ByteString, Bytes: h.ArtifactDigest[:]}, {Name: "candidate_id", Kind: protocolv4.ByteString, Bytes: candidateID},
		{Name: "route_digest", Kind: protocolv4.ByteString, Bytes: h.BrowserRouteDigest[:]}, {Name: "attempt_id", Kind: protocolv4.ByteString, Bytes: h.Hello.Attempt[:]},
		{Name: "client_nonce", Kind: protocolv4.ByteString, Bytes: nonce}, {Name: "offered_features", Number: h.Hello.Offered},
		{Name: "supported_binding_modes", Number: uint64(h.Hello.BindingModes)}, {Name: "client_identity_hint", Kind: protocolv4.ByteString, Bytes: []byte{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func newRegistryServer(t *testing.T) (context.Context, *Server, *AcceptedRegistry) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	reporter, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reporter.Close(); err != nil {
			t.Error(err)
		}
	})
	server, err := NewServer(ctx, reporter, ServerOptions{Carrier: "websocket", Handlers: manualEchoPlan})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewAcceptedRegistry(2)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, server, registry
}

func TestAcceptedSourceReuseCannotClaimAnotherOriginalRecord(t *testing.T) {
	ctx, server, registry := newRegistryServer(t)
	first, err := registry.Install(server.Runtime.Authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	_, _, policy, err := directRoute(server.Material().Route)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := server.IssueAuthority(policy, server.Address)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.Install(authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
	})
	position, err := server.NewAcceptedPosition(registry, manualEchoPlan)
	if err != nil {
		t.Fatal(err)
	}
	source := position.acceptedSource.(*AcceptedRegistrySource)
	if material, _, err := source.ResolveAcceptedMaterial(ctx, registryHello(t, first.Authority)); err != nil || material == nil {
		t.Fatalf("original first lookup: %v", err)
	}
	if material, _, err := source.ResolveAcceptedMaterial(ctx, registryHello(t, second.Authority)); err == nil || material != nil {
		t.Fatal("one original accepted position claimed another lease")
	}
	if !first.Claimed() || second.Claimed() || registry.PendingCount() != 1 {
		t.Fatal("reused source changed another original record's claim")
	}
	if position.Runtime.Authorized[1].Load() != 0 {
		t.Fatal("lookup was reported as authenticated application admission")
	}
}

func TestAcceptedRegistryConcurrentClaimAndWithdrawal(t *testing.T) {
	ctx, server, registry := newRegistryServer(t)
	record, err := registry.Install(server.Runtime.Authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := record.Close(); err != nil {
			t.Error(err)
		}
	})
	var positions [2]*Server
	for index := range positions {
		positions[index], err = server.NewAcceptedPosition(registry, manualEchoPlan)
		if err != nil {
			t.Fatal(err)
		}
		reporter := positions[index].Runtime.Reporter
		t.Cleanup(func() {
			if err := reporter.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	hello := registryHello(t, record.Authority)
	type lookupResult struct {
		material *fs.ConnectionMaterial
		err      error
	}
	results := make(chan lookupResult, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for _, position := range positions {
		source := position.acceptedSource.(*AcceptedRegistrySource)
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			material, _, err := source.ResolveAcceptedMaterial(ctx, hello)
			results <- lookupResult{material, err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result.err == nil && result.material != nil {
			successes++
		} else if result.err == nil || result.material != nil {
			t.Fatal("lookup published an inconsistent material/error result")
		}
	}
	if successes != 1 || !record.Claimed() || registry.PendingCount() != 0 {
		t.Fatalf("original claim winners = %d", successes)
	}
	if err := record.Close(); err != nil {
		t.Fatal(err)
	}
	for _, position := range positions {
		position.acceptedSource.(*AcceptedRegistrySource).Deliver(position, nil, nil)
	}
	if session, err := record.WaitSession(ctx); err == nil || session != nil {
		t.Fatal("withdrawn original material published an acceptance result")
	}
	for _, position := range positions {
		if position.Runtime.Authorized[1].Load() != 0 {
			t.Fatal("source claim synthesized application admission")
		}
	}
}

func TestFailedAcceptedPositionRetiresOnlyItsOwnGraph(t *testing.T) {
	_, server, registry := newRegistryServer(t)
	reporter := server.Runtime.Reporter
	reporter.mu.Lock()
	callbacks := len(reporter.cleanup)
	reporter.mu.Unlock()
	rootBefore := server.Runtime.Authority.Root.Snapshot()
	want := errors.New("original application plan construction failed")
	reject := func(*Runtime, uint8) (fs.StreamHandlerPlanConfig, error) { return fs.StreamHandlerPlanConfig{}, want }
	if position, err := server.NewAcceptedPosition(registry, reject); !errors.Is(err, want) || position != nil {
		t.Fatalf("failed original position construction = %v", err)
	}
	reporter.mu.Lock()
	after := len(reporter.cleanup)
	reporter.mu.Unlock()
	if callbacks != after {
		t.Fatal("failed position retained a parent cleanup callback")
	}
	rootAfter := server.Runtime.Authority.Root.Snapshot()
	if rootBefore.Charged != rootAfter.Charged {
		t.Fatalf("failed original position retained resources: before=%v after=%v", rootBefore.Charged, rootAfter.Charged)
	}
	if reporter.closed {
		t.Fatal("failed child position closed the original listener authority")
	}
}

func TestAcceptedMaterialsSourceReusePreservesOtherOriginalRecord(t *testing.T) {
	ctx, server, _ := newRegistryServer(t)
	_, _, policy, err := directRoute(server.Material().Route)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := server.IssueAuthority(policy, server.Address)
	if err != nil {
		t.Fatal(err)
	}
	materials := NewAcceptedMaterials(server.Runtime.Authority, authority)
	position, err := server.NewHTTPAcceptPosition(materials, manualEchoPlan)
	if err != nil {
		t.Fatal(err)
	}
	source := position.acceptedSource
	if material, _, err := source.ResolveAcceptedMaterial(ctx, registryHello(t, server.Runtime.Authority)); err != nil || material == nil {
		t.Fatalf("first original material lookup: %v", err)
	}
	if material, _, err := source.ResolveAcceptedMaterial(ctx, registryHello(t, authority)); err == nil || material != nil {
		t.Fatal("one original material view claimed a second installed record")
	}
	materials.mu.Lock()
	claimed := materials.claimed
	materials.mu.Unlock()
	if !claimed[0] || claimed[1] {
		t.Fatal("reused original view changed the other record's claim")
	}
	if position.Runtime.Authorized[1].Load() != 0 {
		t.Fatal("material lookup synthesized authenticated admission")
	}
}

func TestAcceptedRecordWaitPreservesOriginalFailureForAllObservers(t *testing.T) {
	ctx, server, registry := newRegistryServer(t)
	record, err := registry.Install(server.Runtime.Authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := record.Close(); err != nil {
			t.Error(err)
		}
	})
	position, err := server.NewAcceptedPosition(registry, manualEchoPlan)
	if err != nil {
		t.Fatal(err)
	}
	source := position.acceptedSource.(*AcceptedRegistrySource)
	if material, _, err := source.ResolveAcceptedMaterial(ctx, registryHello(t, record.Authority)); err != nil || material == nil {
		t.Fatalf("original lookup: %v", err)
	}
	want := errors.New("original acceptance failed before publication")
	source.Deliver(position, nil, want)
	canceled, stop := context.WithCancel(ctx)
	stop()
	if session, err := record.WaitSession(canceled); session != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled observer consumed the delivered outcome: %v", err)
	}
	for index := 0; index < 2; index++ {
		if session, err := record.WaitSession(ctx); session != nil || !errors.Is(err, want) {
			t.Fatalf("observer %d lost the original acceptance failure: %v", index, err)
		}
	}
	if position.Runtime.Authorized[1].Load() != 0 {
		t.Fatal("failed callback synthesized authenticated admission")
	}
}

func TestAcceptedRecordDuplicateDeliveryKeepsOriginalAuthenticatedSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	reporter, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reporter.Close(); err != nil {
			t.Error(err)
		}
	})
	registry, err := NewAcceptedRegistry(1)
	if err != nil {
		t.Fatal(err)
	}
	positions := make(chan *Server, 1)
	ready := make(chan struct{})
	var server *Server
	server, err = NewServer(ctx, reporter, ServerOptions{Carrier: "websocket", Handlers: manualEchoPlan, NextAccepted: func(ctx context.Context, listener *Server) (*Server, error) {
		select {
		case <-ready:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
		position, err := server.NewAcceptedPosition(registry, manualEchoPlan)
		if err == nil {
			positions <- position
		}
		return position, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := registry.Install(server.Runtime.Authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := record.Close(); err != nil {
			t.Error(err)
		}
	})
	close(ready)
	wire, err := server.Material().JSON()
	if err != nil {
		t.Fatal(err)
	}
	clientReporter, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := clientReporter.Close(); err != nil {
			t.Error(err)
		}
	})
	client, err := NewClient(ctx, clientReporter, wire, server.TrustPEM, server.Origin, manualEchoPlan)
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := record.WaitSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var position *Server
	select {
	case position = <-positions:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	source := position.acceptedSource.(*AcceptedRegistrySource)
	source.Deliver(position, accepted, nil)
	if again, err := record.WaitSession(ctx); err != nil || again != accepted {
		t.Fatalf("repeated observer lost the original Session: %v", err)
	}
	opened, err := session.OpenStream(ctx, "engineering/manual", fs.EmptyStreamMetadata())
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := accepted.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if incoming.Kind != "engineering/manual" {
		t.Fatal("duplicate callback changed original stream dispatch")
	}
	replied := make(chan error, 1)
	go func() {
		payload, err := io.ReadAll(incoming.Stream)
		if err == nil && string(payload) != "request" {
			err = errors.New("original manual stream input changed")
		}
		if err == nil {
			_, err = incoming.Stream.WriteAll(ctx, []byte("response"))
		}
		if err == nil {
			err = incoming.Stream.Finish(ctx)
		}
		replied <- err
	}()
	if _, err = opened.WriteAll(ctx, []byte("request")); err != nil {
		t.Fatal(err)
	}
	if err = opened.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(opened)
	if err != nil || string(reply) != "response" {
		t.Fatalf("original manual response after duplicate callback: %q %v", reply, err)
	}
	if err = opened.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-replied:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if position.Runtime.Authorized[1].Load() != 1 || client.Runtime.SourceAcquisitions.Load() != 1 || !client.Runtime.PoolSpend.Snapshot().CommitKnown {
		t.Fatal("duplicate callback changed original source/admission ownership")
	}
	// FIN drains output; release both original stream capabilities before
	// asking the Session to join its physical cleanup.
	if err = opened.Close(); err != nil {
		t.Fatal(err)
	}
	if err = incoming.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err = record.Close(); err != nil {
		t.Fatal(err)
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	if err = session.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptedClosedErrorsPreserveUnexpectedJoinedCauses(t *testing.T) {
	unexpected := errors.New("unexpected original cleanup failure")
	for _, cause := range []error{unexpected, native.ErrConnectionLost} {
		joined := errors.Join(net.ErrClosed, cause)
		remaining := filterAcceptedClosedErrors(joined)
		if !errors.Is(remaining, cause) || errors.Is(remaining, net.ErrClosed) {
			t.Fatalf("joined original cleanup: %v", remaining)
		}
		if remaining := filterAcceptedClosedErrors(fmt.Errorf("cleanup: %w", joined)); !errors.Is(remaining, cause) {
			t.Fatalf("wrapped cleanup failure hidden: %v", remaining)
		}
	}
	if remaining := filterAcceptedClosedErrors(fmt.Errorf("cleanup: %w", net.ErrClosed)); remaining != nil {
		t.Fatalf("proven closed cleanup retained: %v", remaining)
	}
}
