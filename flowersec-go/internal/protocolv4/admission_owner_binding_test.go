package protocolv4

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func TestActivationOriginalBindingPreservesEarlierActivationCap(t *testing.T) {
	f := newNamespaceFixture(t)
	artifact, authority, _ := f.activation(t, "live_authority")
	session, err := artifact.SessionParameters()
	if err != nil {
		t.Fatal(err)
	}
	b := authority.binding
	if b.sessionEnd >= session.SessionNotAfterMS {
		t.Fatal("fixture must have a tighter activation cap")
	}
	for _, check := range []func(ArtifactSessionParameters, [16]byte, PoolMember) error{b.MatchOriginal, authority.MatchOriginal} {
		if err := check(session, b.attempt, b.winner); err != nil {
			t.Fatal("original signed end confused with activation cap", err)
		}
		for _, name := range []string{"contract", "artifact", "profile", "attempt", "index", "candidate", "route"} {
			s, a, w := session, b.attempt, b.winner
			switch name {
			case "contract":
				s.Contract = SessionContract{}
			case "artifact":
				s.ArtifactDigest[0] ^= 1
			case "profile":
				s.Profile += "other"
			case "attempt":
				a[0] ^= 1
			case "index":
				w.Index++
			case "candidate":
				w.CandidateID[0] ^= 1
			case "route":
				w.RouteDigest[0] ^= 1
			}
			if check(s, a, w) == nil {
				t.Fatal("replacement accepted", name)
			}
		}
	}
	if (*ActivationBinding)(nil).MatchOriginal(session, b.attempt, b.winner) == nil || (*ActivationAuthority)(nil).MatchOriginal(session, b.attempt, b.winner) == nil || (&ActivationAuthority{}).MatchOriginal(session, b.attempt, b.winner) == nil {
		t.Fatal("nil binding accepted")
	}
}

func TestCredentialPreparationBindsEnvironmentAndOriginalClosure(t *testing.T) {
	x := newEndpointCredentialFixture(t, false, false)
	x.f.now = timev4.Interval{LowerMS: 1200, UpperMS: 1250}
	closure, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	n, _, trust := liveNamespaceFixture(t, x.f, 4000, false)
	policy := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
	var bindings [3]CredentialValidation
	for i, c := range closure.credentials[:closure.count] {
		bindings[i] = CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: c.scope.Schema, Issuer: c.scope.Issuer, Key: c.key, SigningStart: 1000, SigningEnd: 1100}, Policy: policy}
	}
	s, err := closure.Subscribe(bindings[:], 5000, x.f.reserve(t, CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	environment := x.f.reserve(t, resourcev4.Vector{resourcev4.Items: 1})
	session, err := x.originals[0].SessionParameters()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CheckPreparationFor(environment); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CheckOriginalFor(environment, session, ClientToServer, closure.selection); err != nil {
		t.Fatal(err)
	}
	otherOwner := x.f.resourceOwner()
	otherOwner.Environment = [16]byte{2}
	other, err := x.f.resources.Reserve(otherOwner, resourcev4.Vector{resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	private := newNamespaceFixture(t).reserve(t, resourcev4.Vector{resourcev4.Items: 1})
	for _, reference := range []resourcev4.Reference{other, private, {}} {
		if _, err = s.CheckPreparationFor(reference); err == nil {
			t.Fatal("cross-Environment accepted")
		}
		if _, err = s.CheckOriginalFor(reference, session, ClientToServer, closure.selection); err == nil {
			t.Fatal("original bypassed Environment")
		}
	}
	for _, name := range []string{"contract", "artifact", "profile", "role", "index", "candidate", "route"} {
		copySession, role, winner := session, ClientToServer, closure.selection
		switch name {
		case "contract":
			copySession.Contract = SessionContract{}
		case "artifact":
			copySession.ArtifactDigest[0] ^= 1
		case "profile":
			copySession.Profile += "other"
		case "role":
			role = ServerToClient
		case "index":
			winner.Index++
		case "candidate":
			winner.CandidateID[0] ^= 1
		case "route":
			winner.RouteDigest[0] ^= 1
		}
		if _, err = s.CheckOriginalFor(environment, copySession, role, winner); err == nil {
			t.Fatal("replacement accepted", name)
		}
	}
	if _, err = s.CheckPreparationFor(environment); err != nil {
		t.Fatal("failed comparison consumed original", err)
	}
	trust.rejected.Store(true)
	if _, err = s.CheckOriginalFor(environment, session, ClientToServer, closure.selection); err == nil {
		t.Fatal("current trust rejection ignored")
	}
	if n.SubscriptionCount() != 0 {
		t.Fatal("failed preparation retained subscriptions")
	}
	if _, err = s.CheckPreparationFor(environment); err != CBORFailure("credential_authorization_owner") {
		t.Fatal("closed preparation accepted", err)
	}
	if _, err = s.CheckOriginalFor(environment, session, ClientToServer, closure.selection); err != CBORFailure("credential_authorization_owner") {
		t.Fatal("closed original preparation accepted", err)
	}
	if _, err = (*CredentialSubscriptions)(nil).CheckPreparationFor(environment); err == nil {
		t.Fatal("nil accepted")
	}
	if _, err = (*CredentialSubscriptions)(nil).CheckOriginalFor(environment, session, ClientToServer, closure.selection); err == nil {
		t.Fatal("nil original accepted")
	}
}

func TestCredentialOriginalPreparationRejectsTransferredOwner(t *testing.T) {
	x := newEndpointCredentialFixture(t, false, false)
	x.f.now = timev4.Interval{LowerMS: 1200, UpperMS: 1250}
	closure, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	n, _, trust := liveNamespaceFixture(t, x.f, 4000, false)
	policy := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
	var bindings [3]CredentialValidation
	for i, c := range closure.credentials[:closure.count] {
		bindings[i] = CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: c.scope.Schema, Issuer: c.scope.Issuer, Key: c.key, SigningStart: 1000, SigningEnd: 1100}, Policy: policy}
	}
	s, err := closure.Subscribe(bindings[:], 5000, x.f.reserve(t, CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, activation, _ := x.f.activationOriginal(t, "live_authority", x.originals[0])
	trust.activation = activation.trust
	authorization, err := NewEndpointAuthorization(s, activation)
	if err != nil {
		t.Fatal(err)
	}
	defer authorization.Close(nil)
	environment := x.f.reserve(t, resourcev4.Vector{resourcev4.Items: 1})
	session, err := x.originals[0].SessionParameters()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CheckPreparationFor(environment); err != CBORFailure("credential_authorization_owner") {
		t.Fatal("transferred preparation accepted", err)
	}
	if _, err = s.CheckOriginalFor(environment, session, ClientToServer, closure.selection); err != CBORFailure("credential_authorization_owner") {
		t.Fatal("transferred original preparation accepted", err)
	}
	if err = authorization.Check(); err != nil {
		t.Fatal("stale preparation modified authorization", err)
	}
}
