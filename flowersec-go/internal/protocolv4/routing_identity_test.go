package protocolv4

import "testing"

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
