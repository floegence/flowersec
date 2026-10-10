package sessionv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestEstablishmentHandshakeCopiesKeepOriginalBytesAndDeclaredRefusal(t *testing.T) {
	f, _, client, fsb := acceptedVerifiedFlight(t)
	binding, err := client.hello.MatchFSB(f.trust.activation, fsb, f.trust.certificates[0])
	if err != nil {
		t.Fatal(err)
	}
	identity, err := f.trust.certificates[1].Digest("certificate_digest")
	if err != nil {
		t.Fatal(err)
	}
	codec, err := protocolv4.NewSignedMapCodec("FSA4", 16384, 4096)
	if err != nil {
		t.Fatal(err)
	}
	fsa, err := client.hello.BuildResponse(codec, f.trust.certificates[1], protocolv4.AdmissionResponse{Admitted: true, ServerEpoch: 1, ReservationKey: [32]byte{4}, AdmissionBinding: binding, ServerIdentityDigest: identity}, f.trust.signers[1], func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer fsa.Release()
	material, err := client.hello.BindHandshakeMaterial(f.trust.artifact, f.trust.activation, f.trust.certificates[0], f.trust.certificates[1], fsb, fsa)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Close()
	fsbWire, err := fsb.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	fsaWire, err := fsa.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	originalFSB, originalFSA := bytes.Clone(fsbWire), bytes.Clone(fsaWire)
	if max(len(fsbWire), len(fsaWire)) >= 65536 {
		t.Fatal("fixture does not distinguish actual messages from the declared allowance")
	}
	// The signed-flight fixture has not run admission's tightening of this
	// original stage deadline to the activation and certificate Session caps.
	authorization, ok := client.config.Authorization.(*protocolv4.EndpointAuthorization)
	if !ok {
		t.Fatal("fixture does not retain the original endpoint authorization")
	}
	if err := authorization.ConstrainHandshakeDeadline(client.config.Deadline); err != nil {
		t.Fatal(err)
	}
	_, sessionEnd := f.trust.activation.Deadlines()
	clientEnd, _ := f.trust.certificates[0].Field("expires_at_ms").Uint()
	serverEnd, _ := f.trust.certificates[1].Field("expires_at_ms").Uint()
	if client.config.Deadline != f.config.Initial.Deadline || client.config.Deadline.Cap() > min(sessionEnd, clientEnd, serverEnd) {
		t.Fatal("fixture did not tighten the original deadline to the bound Session caps")
	}
	if err := client.config.Deadline.Check(); err != nil {
		t.Fatal("original tightened deadline is unavailable", err)
	}
	if err := authorization.Check(); err != nil {
		t.Fatal("original endpoint authorization is unavailable", err)
	}
	p := &SessionEstablishment{&sessionEstablishment{fsb: fsb, fsa: fsa, mapBytes: 65536}}
	keys := cryptov4.AdmissionKeyConfig{Role: protocolv4.ClientToServer, LocalDH: f.trust.keys[0], Signer: f.trust.signers[0], Deadline: client.config.Deadline, Clock: f.trust.clock, SessionDeadlineMS: sessionEnd, Authorization: authorization}
	for _, limit := range []int{len(fsbWire) - 1, len(fsaWire) - 1} {
		p.mapBytes = limit
		invalid := keys
		invalid.LocalDH = nil
		if _, err := p.admissionHandshakeConfig(material, invalid); !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal("copy capacity changed the original local-input refusal order", err)
		}
		if config, err := p.admissionHandshakeConfig(material, keys); config.FSB != nil || config.FSA != nil || err != protocolv4.CBORFailure("encoder_capacity") {
			t.Fatal("actual-sized allocation widened the original two-map capacity", limit, err)
		}
	}
	for _, limit := range []int{65536, max(len(fsbWire), len(fsaWire))} {
		p.mapBytes = limit
		config, err := p.admissionHandshakeConfig(material, keys)
		if err != nil {
			t.Fatal("capacity refusal prevented a later original configuration", err)
		}
		if len(config.FSB) != len(fsbWire) || cap(config.FSB) != len(fsbWire) || len(config.FSA) != len(fsaWire) || cap(config.FSA) != len(fsaWire) || !bytes.Equal(config.FSB, originalFSB) || !bytes.Equal(config.FSA, originalFSA) {
			t.Fatal("private copies retained full allowance or changed original admission bytes")
		}
		handshake, err := cryptov4.NewHandshake(config)
		clear(config.PSK[:])
		if err != nil {
			clear(config.FSB)
			clear(config.FSA)
			t.Fatal("exact copies changed the bound Noise configuration", err)
		}
		handshake.Close()
		clear(config.FSB)
		clear(config.FSA)
		if !bytes.Equal(fsbWire, originalFSB) || !bytes.Equal(fsaWire, originalFSA) {
			t.Fatal("copy cleanup erased the retained original signed maps")
		}
	}
}

type establishmentLiveAllowProvider struct {
	entered, release chan struct{}
	request          TunnelServerAllowRequest
	material         [2][]byte
}

func (p *establishmentLiveAllowProvider) PublishServerAllow(context.Context, TunnelServerAllowRequest, []byte, func() error) error {
	return cryptov4.ErrConfiguration
}

func (p *establishmentLiveAllowProvider) PublishOriginalLiveServerAllow(_ context.Context, request TunnelServerAllowRequest, material [2][]byte, guard func() error) error {
	if err := guard(); err != nil {
		return err
	}
	p.request, p.material = request, material
	close(p.entered)
	<-p.release
	return nil
}

func TestEstablishmentLiveTunnelScratchPreservesRequestAndPublicationTail(t *testing.T) {
	bundle := newImmutableLiveTunnelBundle(t, protocolv4.ClientToServer)
	f := bundle.f
	limits := EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
	charge, err := EstablishmentCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	p, subscriptions, err := bundle.material.Establishment(InitialHello{Index: 0, Attempt: f.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}, limits, bundle.material.generation, bundle.reserve(charge), bundle.reserve(protocolv4.CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer subscriptions.Close()
	t.Cleanup(func() {
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	})
	tunnel := &protocolv4.LiveTunnelActivationConfig{Client: f.trust.certificates[0], Server: f.trust.certificates[1], Relay: bundle.tunnel.relay}
	for index := range 3 {
		tunnel.Bindings[index] = protocolv4.CredentialValidation{Namespace: f.trust.namespace, Issuer: f.trust.trust.permissions[index], Policy: f.trust.trust.policy}
	}
	validation := func(original *protocolv4.SignedMap) protocolv4.CredentialValidation {
		credential, err := original.DetachCredential()
		if err != nil {
			t.Fatal(err)
		}
		for _, authority := range f.trust.trust.additional {
			if authority.scope == credential.Scope() {
				return protocolv4.CredentialValidation{Namespace: f.trust.namespace, Issuer: authority.permission, Policy: f.trust.trust.policy}
			}
		}
		t.Fatal("original tunnel validation is missing")
		return protocolv4.CredentialValidation{}
	}
	registry, err := authorityRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for side, grant := range bundle.tunnel.grants {
		for _, field := range registry.Maps["Grant"].Fields {
			if field.Name == "signature" {
				continue
			}
			value := admissionField(grant.Field(field.Name))
			value.Name = field.Name
			tunnel.Grants[side].Fields = append(tunnel.Grants[side].Fields, value)
		}
		tunnel.Grants[side].Signer = bootstrapSigner{ed25519.NewKeyFromSeed(bundle.tunnel.recipe.GrantIssuerSeed[:])}
		tunnel.Bindings[3+2*side] = validation(grant)
		tunnel.Bindings[4+2*side] = validation(bundle.tunnel.relay)
	}
	planCharge, err := protocolv4.LiveActivationPlanCharge(true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := protocolv4.NewLiveActivationPlan(f.trust.artifact, f.trust.rules, f.trust.delegation, f.trust.once, f.trust.issueSigner, protocolv4.LiveActivationConfig{Tunnel: tunnel, Index: 0, Attempt: f.trust.attempt, IssuedAt: 1150, ActivationEnd: 1400, SessionEnd: 4000}, bundle.reserve(planCharge), f.environment, f.preauth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := plan.Close(); err != nil {
			t.Error(err)
		}
	})
	provider := &establishmentLiveAllowProvider{entered: make(chan struct{}), release: make(chan struct{})}
	publication := LiveServerAllowConfig{Provider: provider, Recipient: [16]byte{1}, Incarnation: [16]byte{2}}
	invalid := publication
	invalid.Recipient = [16]byte{}
	if _, err := p.liveServerAllowRequest(plan, invalid, 1400); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("live tunnel accepted an incomplete recipient after copying", err)
	}
	request, err := p.liveServerAllowRequest(plan, publication, 1400)
	if err != nil {
		t.Fatal("request refusal consumed the original frozen projection", err)
	}
	again, err := p.liveServerAllowRequest(plan, publication, 1400)
	if err != nil || again != request || request.Tenant == "" || request.Audience == "" {
		t.Fatal("erased scratch changed the detached live tunnel request", err)
	}
	proofLimit, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	grantLimit, _ := protocolv4.SchemaByteLimit("Grant")
	backing := [3][]byte{make([]byte, proofLimit), make([]byte, grantLimit), make([]byte, grantLimit)}
	defer func() {
		for _, bytes := range backing {
			clear(bytes)
		}
	}()
	sizes, err := plan.IssueMaterial(backing, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	material := [2][]byte{backing[0][:sizes[0]:sizes[0]], backing[2][:sizes[2]:sizes[2]]}
	original := [2][]byte{bytes.Clone(material[0]), bytes.Clone(material[1])}
	if err := p.begin(protocolv4.ClientToServer); err != nil {
		t.Fatal(err)
	}
	guard := func() error {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return cryptov4.ErrClosed
		}
		return p.reservation.Check()
	}
	done := make(chan error, 1)
	go func() {
		err := PublishOriginalLiveServerAllow(context.Background(), provider, request, material, guard)
		for _, bytes := range material {
			clear(bytes)
		}
		p.finish(err)
		done <- err
	}()
	select {
	case <-provider.entered:
	case <-time.After(time.Second):
		close(provider.release)
		<-done
		t.Fatal("original live tunnel publication did not enter its provider")
	}
	held := f.root.Snapshot().Charged
	p.Close()
	retireErr := p.Retire()
	if !errors.Is(retireErr, cryptov4.ErrCapacity) || p.reservation.CheckRetained() != nil || p.shared.CheckRetained() != nil || f.root.Snapshot().Charged != held || provider.request != request || !bytes.Equal(provider.material[0], original[0]) || !bytes.Equal(provider.material[1], original[1]) {
		close(provider.release)
		<-done
		t.Fatal("Close erased or refunded original publication material before provider exit", retireErr)
	}
	if err := p.begin(protocolv4.ClientToServer); !errors.Is(err, cryptov4.ErrTransition) {
		close(provider.release)
		<-done
		t.Fatal("an active original publication admitted another connection", err)
	}
	close(provider.release)
	if err := <-done; !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("late publication bypassed the original close guard", err)
	}
	for _, retained := range provider.material {
		if !bytes.Equal(retained, make([]byte, len(retained))) {
			t.Fatal("publication material survived the actual provider return")
		}
	}
	if err := p.Retire(); err != nil {
		t.Fatal(err)
	}
}

func TestEstablishmentLiveProjectionCapacityFailureDoesNotConsumePlan(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "live_authority")
	cost, err := protocolv4.LiveActivationPlanCharge()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 350), cost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	plan, err := protocolv4.NewLiveActivationPlan(f.trust.artifact, f.trust.rules, f.trust.delegation, f.trust.once, f.trust.issueSigner, protocolv4.LiveActivationConfig{Index: 0, Attempt: f.trust.attempt, IssuedAt: 1150, ActivationEnd: 1400, SessionEnd: 4000}, ref, f.environment, f.preauth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := plan.Close(); err != nil {
			t.Error(err)
		}
	})
	projection := make([]byte, 4096)
	fields, n, err := plan.CopyProjection(projection)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(projection[:n])
	p := &SessionEstablishment{&sessionEstablishment{mapBytes: n - 1}}
	if request, err := p.liveServerAllowRequest(plan, LiveServerAllowConfig{}, 1400); request != (TunnelServerAllowRequest{}) || err != protocolv4.CBORFailure("configuration_capacity") {
		t.Fatal("live projection changed the original full-map refusal order", err)
	}
	p.mapBytes = 65536
	// Request validation fails only after copying; neither failure may issue or
	// replace the authority's frozen original projection.
	if request, err := p.liveServerAllowRequest(plan, LiveServerAllowConfig{}, 1400); request != (TunnelServerAllowRequest{}) || !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("invalid live publication request was accepted", err)
	}
	clear(projection)
	again, used, err := plan.CopyProjection(projection)
	if err != nil || again != fields || used != n || !bytes.Equal(projection[:used], original) {
		t.Fatal("scoped scratch cleanup changed or consumed the original live projection", err)
	}
}
