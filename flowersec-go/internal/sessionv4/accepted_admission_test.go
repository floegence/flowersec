package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func acceptedAdmissionFixture(t *testing.T, configure ...func(*admissionIntegrationFixture, *SessionAdmissionConfig)) (*admissionIntegrationFixture, *AcceptedEntrance, *InitialExchange, *SessionAdmissionReservation, *protocolv4.SignedMap) {
	t.Helper()
	f, e, client, fsb := acceptedVerifiedFlight(t)
	c := f.config
	c.Core.MessageCarrier = false
	c.Initial.Role = protocolv4.ServerToClient
	for _, configure := range configure {
		configure(f, &c)
	}
	a, err := NewAcceptedSessionAdmissionReservation(context.Background(), c, e, AcceptedAdmissionMaterial{Activation: f.trust.activation, Authority: f.trust.authority, FSB: fsb, ClientCertificate: f.trust.certificates[0], Subscriptions: f.trust.subscriptions[1], Attempt: f.trust.attempt}, f.root, admissionResourceKey(f.owner, 213), f.environment, f.preauth, f.scope)
	if a != nil {
		t.Cleanup(func() {
			a.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := a.WaitCleanup(ctx); err != nil {
				t.Error(err)
				return
			}
			if err := a.Retire(); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	return f, e, client, a, fsb
}

func TestAcceptedAdmissionKeepsOriginalInitialAndSessionBeforeClaim(t *testing.T) {
	f, e, _, a, _ := acceptedAdmissionFixture(t)
	if a.initial != e.initial || a.prepared != e.carrier || a.activated {
		t.Fatal("accepted token replaced or activated original entrance")
	}
	used, err := f.scope.Session.Usage()
	if err != nil || used[resourcev4.Sessions] != 1 {
		t.Fatal("Session quota not reserved before claim", used, err)
	}
	if err := e.guard.checkAdmitted(); !errors.Is(err, ErrAdmissionRejected) {
		t.Fatal("local resources granted admission", err)
	}
	if _, err := a.activate(f.trust.authority); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("consumer Activate accepted server entrance", err)
	}
	x, _ := admitAcceptedSQLite(t, f, a)
	if x != e.initial {
		t.Fatal("original CAS did not retain Initial")
	}
	if _, err := a.beginClaim(); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("admit continuation repeated", err)
	}
}

func TestAcceptedAdmissionRejectsChangedFSABeforeSigningAndPublication(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "builder", true: "raw"}[raw], func(t *testing.T) {
			f, e, client, a, _ := acceptedAdmissionFixture(t)
			server, response := admitAcceptedSQLite(t, f, a)
			codec, err := protocolv4.NewSignedMapCodec("FSA4", 16384, 4096)
			if err != nil {
				t.Fatal(err)
			}
			response.AdmissionBinding[0] ^= 1
			done := make(chan error, 1)
			go func() { done <- client.Receive(protocolv4.FrameAdmissionResult, func([]byte) error { return nil }) }()
			var signed *protocolv4.SignedMap
			var result InitialWriteResult
			if raw {
				signed, err = server.hello.BuildResponse(codec, f.trust.certificates[1], response, f.trust.signers[1], func() error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				wire, wireErr := signed.Bytes()
				if wireErr != nil {
					t.Fatal(wireErr)
				}
				result, err = server.Send(protocolv4.FrameAdmissionResult, initialCopy(wire))
			} else {
				signed, result, err = server.SendAdmissionResponse(codec, f.trust.certificates[1], response, f.trust.signers[1], func() error { return e.guard.checkAdmitted() })
				if signed != nil {
					t.Error("changed FSA reached signer")
				}
			}
			if signed != nil {
				signed.Release()
			}
			client.Close(cryptov4.ErrClosed)
			<-done
			if err != protocolv4.CBORFailure("admission_response_binding") || result.Submitted {
				t.Fatal("changed FSA published", result, err)
			}
		})
	}
}

func TestAcceptedAdmissionSignedRejectionNeverGrantsNoise(t *testing.T) {
	f, e, client, a, _ := acceptedAdmissionFixture(t)
	serverCodec, err := protocolv4.NewSignedMapCodec("FSA4", 16384, 4096)
	if err != nil {
		t.Fatal(err)
	}
	clientCodec, err := protocolv4.NewSignedMapCodec("FSA4", 16384, 4096)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := client.admissionHello()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- client.Receive(protocolv4.FrameAdmissionResult, func(wire []byte) error {
			signed, err := clientCodec.Verify(wire, [32]byte(f.trust.signers[1].PublicKey()), protocolv4.DecodeContext{})
			if err != nil {
				return err
			}
			defer signed.Release()
			response, err := hello.MatchFSA(signed, f.trust.certificates[1], nil, nil, nil)
			if err == nil && (response.Admitted || response.Code != 1) {
				return cryptov4.ErrTransition
			}
			return err
		})
	}()
	fsa, result, err := e.initial.SendAdmissionResponse(serverCodec, f.trust.certificates[1], protocolv4.AdmissionResponse{Code: 1}, f.trust.signers[1], func() error { return nil })
	if fsa != nil {
		fsa.Release()
	}
	if !errors.Is(err, ErrAdmissionRejected) || !result.Complete {
		t.Fatal("signed rejection not delivered", result, err)
	}
	if err := <-done; !errors.Is(err, ErrAdmissionRejected) {
		t.Fatal(err)
	}
	if a.claimed || a.committed || a.activated {
		t.Fatal("rejection acquired a continuation")
	}
	if err := e.guard.checkAdmitted(); err == nil {
		t.Fatal("rejection revived admission")
	}
}

func TestAcceptedAdmissionLateClaimKeepsOriginalPreauthAndSession(t *testing.T) {
	f, _, _, a, _ := acceptedAdmissionFixture(t)
	claim, err := a.beginClaim()
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot().Charged
	a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := a.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("late store owner detached", err)
	}
	// Trust subscriptions may close on logical termination. All original
	// preauth/core transport and the real Session position remain charged.
	if f.root.Snapshot().Charged[resourcev4.Sessions] != before[resourcev4.Sessions] {
		t.Fatal("pending store refunded Session")
	}
	if err := a.finishClaim(claim, true); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("late admitted claim revived FSA", err)
	}
	if err := a.accepted.guard.checkAdmitted(); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("closed admitted gate reopened", err)
	}
}

func TestAcceptedAdmissionInvalidFSBBindingDoesNotAcquireSession(t *testing.T) {
	f, e, _, fsb := acceptedVerifiedFlight(t)
	c := f.config
	c.Core.MessageCarrier = false
	c.Initial.Role = protocolv4.ServerToClient
	material := AcceptedAdmissionMaterial{Activation: f.trust.activation, Authority: f.trust.authority, FSB: fsb, ClientCertificate: f.trust.certificates[0], Subscriptions: f.trust.subscriptions[1], Attempt: f.trust.attempt}
	material.Attempt[0] ^= 1
	before := f.root.Snapshot()
	a, err := NewAcceptedSessionAdmissionReservation(context.Background(), c, e, material, f.root, admissionResourceKey(f.owner, 213), f.environment, f.preauth, f.scope)
	if a != nil || err == nil {
		t.Fatal("foreign attempt acquired local admission", err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("failed original comparison retained Session graph")
	}
	if _, err := f.trust.subscriptions[1].CheckOriginalFor(f.environment, f.trust.session, protocolv4.ServerToClient, f.trust.candidate); err != nil {
		t.Fatal("comparison consumed caller subscriptions", err)
	}
}

// This test exercises actual signed FSB/FSA, current trust, both Noise flights
// and dual READY after a real durable SQLite CAS on the original pipe. This
// covers local assembly; distributed deployment qualification remains separate.
func TestAcceptedAdmissionOriginalFSAToNoiseAndDualReady(t *testing.T) {
	f, e, client, a, fsb := acceptedAdmissionFixture(t)
	server, response := admitAcceptedSQLite(t, f, a)
	serverCodec, err := protocolv4.NewSignedMapCodec("FSA4", 16384, 4096)
	if err != nil {
		t.Fatal(err)
	}
	clientCodec, err := protocolv4.NewSignedMapCodec("FSA4", 16384, 4096)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan error, 1)
	go func() {
		received <- client.Receive(protocolv4.FrameAdmissionResult, func(wire []byte) error {
			fsa, err := clientCodec.Verify(wire, [32]byte(f.trust.signers[1].PublicKey()), protocolv4.DecodeContext{})
			if err != nil {
				return err
			}
			defer fsa.Release()
			_, err = client.hello.MatchFSA(fsa, f.trust.certificates[1], f.trust.activation, fsb, f.trust.certificates[0])
			return err
		})
	}()
	fsa, _, err := server.SendAdmissionResponse(serverCodec, f.trust.certificates[1], response, f.trust.signers[1], func() error { return e.guard.checkAdmitted() })
	if fsa != nil {
		defer fsa.Release()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = waitRuntime(t, received); err != nil {
		t.Fatal(err)
	}
	material, err := client.hello.BindHandshakeMaterial(f.trust.artifact, f.trust.activation, f.trust.certificates[0], f.trust.certificates[1], fsb, fsa)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Close()
	c := a.config.Core
	clientPlan, err := NewSessionCorePlan(c, f.root, admissionResourceKey(f.owner, 214), f.environment, corePlanTestScope(t, f.root, f.root.Snapshot().Limit, 2))
	if err != nil {
		t.Fatal(err)
	}
	cleanupCorePlanUnit(t, clientPlan)
	pair := [2]*InitialExchange{client, server}
	var configs [2]cryptov4.HandshakeConfig
	for role := range 2 {
		configs[role], err = cryptov4.AdmissionHandshakeConfig(material, cryptov4.AdmissionKeyConfig{Authorization: pair[role].config.Authorization, Role: protocolv4.Direction(role), LocalDH: f.trust.keys[role], Signer: f.trust.signers[role], Clock: f.trust.clock, Deadline: f.config.Initial.Deadline, SessionDeadlineMS: 5000, LocalIdleDurationMS: c.LocalIdleDurationMS}, make([]byte, 65536), make([]byte, 16384))
		if err != nil {
			t.Fatal(role, err)
		}
	}
	var cores [2]*SessionCore
	finished := make(chan error, 2)
	go func() {
		var err error
		cores[0], err = client.AuthenticateCore(configs[0], clientPlan)
		finished <- err
	}()
	go func() { var err error; cores[1], err = a.Authenticate(configs[1]); finished <- err }()
	for range 2 {
		if err := waitRuntime(t, finished); err != nil {
			t.Fatal(err)
		}
	}
	for role, core := range cores {
		if err := core.Engine().ApplicationInputReady(0); err != nil {
			t.Fatal(role, err)
		}
	}
	if !a.delivered || !server.transferred {
		t.Fatal("dual READY did not transfer original owner")
	}
	if _, err := a.Authenticate(configs[1]); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("duplicate Session delivery", err)
	}
	for i := range configs {
		clear(configs[i].PSK[:])
		clear(configs[i].FSB)
		clear(configs[i].FSA)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, initial := range pair {
		if err := initial.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, core := range cores {
		go func() { finished <- core.Runtime().Run(ctx) }()
	}
	fixtures := [2]initialCoreFixture{{root: f.root, next: 70}, {root: f.root, next: 90}}
	left, right := cores[0].Admission(), cores[1].Admission()
	h, result, err := left.OpenLocal(ctx, BusinessStream, "example/raw", nil, &CarrierAssociation{shared: left.sharedIngress}, fixtures[0].streamReservation(t, cores[0]), streamTestDeadline(t, cores[0].Engine()))
	if err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	peer := OpenHandle{right, h.scope}
	waitCoreOpen(t, right, peer, true)
	if _, err := right.Decide(ctx, peer, BusinessStream, "", fixtures[1].streamReservation(t, cores[1]), right.termination.writer); err != nil {
		t.Fatal(err)
	}
	waitCoreOpen(t, left, h, false)
	clientFlow, err := left.Flow(h)
	if err != nil {
		t.Fatal(err)
	}
	serverFlow, err := right.Flow(peer)
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []struct {
		source, target *StreamFlow
		body           string
	}{{clientFlow, serverFlow, "accepted client payload"}, {serverFlow, clientFlow, "accepted server payload"}} {
		if n, err := direction.source.send.queueOwner.Write(ctx, []byte(direction.body)); err != nil || n != len(direction.body) {
			t.Fatal(n, err)
		}
		var dst [64]byte
		read, err := direction.target.receive.ReadInto(ctx, dst[:])
		if err != nil || string(dst[:read.Progress.Filled]) != direction.body {
			t.Fatal(read, err)
		}
	}
	cores[0].Close()
	a.Close()
	for range 2 {
		_ = waitRuntime(t, finished)
	}
	for _, core := range cores {
		if err := core.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
