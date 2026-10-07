package protocolv4

import (
	"crypto/sha256"
	"testing"
)

func TestRoutingIdentityRetainsAuthenticatedLogicalEndpoints(t *testing.T) {
	e := &EndpointCredentials{role: ClientToServer, count: 3}
	for j := range 3 {
		e.credentials[j] = &Credential{scope: CredentialScope{Tenant: "tenant", Authority: "authority", Audience: "audience", Profile: "profile", Subject: "subject"}}
	}
	original := e.routingIdentity()
	for j := range 3 {
		c := e.credentials[j]
		c.key[0]++
		c.scope.Issuer[0]++
		c.scope.Generation++
		c.scope.ExpiresMS++
		if e.routingIdentity() != original {
			t.Fatal("credential rotation changed logical target")
		}
		for _, field := range []*string{&c.scope.Tenant, &c.scope.Authority, &c.scope.Audience, &c.scope.Subject, &c.scope.Profile} {
			saved := *field
			*field += "-other"
			if e.routingIdentity() == original {
				t.Fatal("different authenticated principal or target matched")
			}
			*field = saved
		}
	}
	e.role = ServerToClient
	if e.routingIdentity() == original {
		t.Fatal("caller direction changed")
	}
}

func TestRoutingIdentityRequiresCurrentAuthorization(t *testing.T) {
	_, a, _, _ := deliveryFixture(t)
	identity, err := a.RoutingIdentity()
	if err != nil || identity == ([32]byte{}) {
		t.Fatal(identity, err)
	}
	a.Close(nil)
	if _, err := a.RoutingIdentity(); err == nil {
		t.Fatal("closed endpoint supplied a routing identity")
	}
}

func TestRoutingIdentityForPeersRequiresTrustedSubjectAndFencesOnlyPeer(t *testing.T) {
	for _, role := range []Direction{ClientToServer, ServerToClient} {
		t.Run(map[Direction]string{ClientToServer: "client", ServerToClient: "server"}[role], func(t *testing.T) {
			e := &EndpointCredentials{role: role, count: 3}
			for j, subject := range []string{"parent", "client", "server"} {
				e.credentials[j] = &Credential{scope: CredentialScope{Tenant: "tenant", Authority: "authority", Audience: "audience", Profile: "profile", Subject: subject}}
			}
			peer := 2
			if role == ServerToClient {
				peer = 1
			}
			var subjects [16][32]byte
			subjects[0] = sha256.Sum256([]byte(e.credentials[peer].scope.Subject))
			subjects[1] = sha256.Sum256([]byte("approved-replica"))
			first, err := e.routingIdentityForPeers(subjects, 2)
			if err != nil {
				t.Fatal(err)
			}
			e.credentials[peer].scope.Subject = "approved-replica"
			second, err := e.routingIdentityForPeers(subjects, 2)
			if err != nil || first != second {
				t.Fatal("approved replica changed stable routing identity", err)
			}
			for j, credential := range e.credentials[:3] {
				fields := []*string{&credential.scope.Tenant, &credential.scope.Authority, &credential.scope.Audience, &credential.scope.Profile}
				if j != peer {
					fields = append(fields, &credential.scope.Subject)
				}
				for _, field := range fields {
					previous := *field
					*field += "-other"
					changed, err := e.routingIdentityForPeers(subjects, 2)
					if err != nil || changed == first {
						t.Fatal("replica mapping weakened another identity fence", j, err)
					}
					*field = previous
				}
			}
			e.credentials[peer].scope.Subject = "unapproved"
			if _, err := e.routingIdentityForPeers(subjects, 2); err != ErrUnapprovedRoutingPeer {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestRoutingIdentityForPeersRetainsCurrentAuthorizationAndFiniteMapping(t *testing.T) {
	_, authorization, namespace, trust := deliveryFixture(t)
	var peers [16][32]byte
	peers[0] = sha256.Sum256([]byte(authorization.closure.credentials[2].scope.Subject))
	original, err := authorization.RoutingIdentityForPeers(peers, 1)
	if err != nil || original == ([32]byte{}) {
		t.Fatal("authenticated approved peer did not supply an identity", original, err)
	}
	for _, count := range []uint8{0, 17, 255} {
		if _, err := authorization.RoutingIdentityForPeers(peers, count); err == nil {
			t.Fatal("invalid finite mapping count accepted", count)
		}
	}
	var other [16][32]byte
	other[0] = sha256.Sum256([]byte("unapproved-peer"))
	if _, err := authorization.RoutingIdentityForPeers(other, 1); err != ErrUnapprovedRoutingPeer {
		t.Fatal("allowlist did not check the currently authenticated peer", err)
	}
	// A rejected routing choice alone does not revoke a healthy endpoint.
	if again, err := authorization.RoutingIdentityForPeers(peers, 1); err != nil || again != original {
		t.Fatal("local mapping refusal changed endpoint authorization", again, err)
	}
	trust.rejected.Store(true)
	namespace.NotifyTrust()
	if _, err := authorization.RoutingIdentityForPeers(peers, 1); err == nil {
		t.Fatal("trusted subject mapping bypassed revoked independent authority")
	}
	trust.rejected.Store(false)
	if _, err := authorization.RoutingIdentityForPeers(peers, 1); err == nil {
		t.Fatal("trusted subject mapping reopened terminally rejected authorization")
	}
}

func TestRoutingIdentityForPeersDoesNotReopenClosedAuthorization(t *testing.T) {
	_, authorization, _, _ := deliveryFixture(t)
	var peers [16][32]byte
	peers[0] = sha256.Sum256([]byte(authorization.closure.credentials[2].scope.Subject))
	authorization.Close(nil)
	if _, err := authorization.RoutingIdentityForPeers(peers, 1); err == nil {
		t.Fatal("closed authorization supplied a mapped routing identity")
	}
	var absent *EndpointAuthorization
	if _, err := absent.RoutingIdentityForPeers(peers, 1); err == nil {
		t.Fatal("absent authorization supplied a mapped routing identity")
	}
}
