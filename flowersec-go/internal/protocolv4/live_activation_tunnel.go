package protocolv4

import (
	"bytes"
	"crypto/sha256"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// LiveGrantProjection is trusted issuer input, never a received Grant. Fields
// contain every unsigned Grant field. Construction copies their exact canonical
// bytes and fixes the independent issuer key before the original TxA.
type LiveGrantProjection struct {
	Fields []Field
	Signer MapSigner
}

// LiveTunnelActivationConfig contains the original full issuer credential
// closure. Bindings are parent/client/server, client Grant/relay, server
// Grant/relay. Each endpoint subsequently receives only its local leg material.
type LiveTunnelActivationConfig struct {
	Client, Server, Relay *SignedMap
	// Issuance derives both original Grant projections from the selected
	// Artifact and the same scopes used during material preparation. It is
	// mutually exclusive with manually supplied Grants.
	Issuance *[2]LiveGrantIssuance
	Grants   [2]LiveGrantProjection
	Bindings [7]CredentialValidation
}

// LiveTunnelLegFields is the immutable public projection of an original Grant.
// It can bind the publication recipient before TxA but grants no signing right.
type LiveTunnelLegFields struct {
	Grant, RelayIdentity [32]byte
	Pairing, Leg         [16]byte
	NotAfterMS           uint64
}

type liveGrantPlan struct {
	codec      *SignedMapCodec
	document   *Document
	credential *Credential
	signer     MapSigner
	key        [32]byte
	unsigned   []byte
	message    []byte
}

type liveTunnelPlan struct {
	grants   [2]liveGrantPlan
	closures [2]*EndpointCredentials
	bindings [2][5]CredentialValidation
	legs     [2]LiveTunnelLegFields
}

// MatchGrantPreparation closes the original source's pending local dependency
// before TxA. A mismatched scope must not be discovered only after consumption.
func (p *LiveActivationPlan) MatchGrantPreparation(role Direction, expected LiveGrantPreparation) error {
	if p == nil || role > ServerToClient {
		return CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.issued || p.active || p.tunnel == nil {
		return CBORFailure("activation_owner")
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	g := &p.tunnel.grants[role]
	if !expected.valid() || g.credential.scope != expected.Scope || p.tunnel.bindings[role][3] != expected.Validation {
		return CBORFailure("credential_grant_preparation")
	}
	return nil
}

func liveTunnelPlanCharge() (resourcev4.Vector, error) {
	limit, err := SchemaByteLimit("Grant")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := SignedMapBackingBytes("Grant", limit, limit)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	closure, err := EndpointCredentialsBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	parent, err := CredentialBackingBytes("Artifact")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	relay, err := CredentialBackingBytes("IdentityCertificate")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: parent + relay + uint64(unsafe.Sizeof(liveTunnelPlan{})) + liveGrantBuilderBackingBytes(limit) + 2*(codec+closure+2*uint64(limit)+1024), resourcev4.Items: 2}, nil
}

func (g *liveGrantPlan) freeze(input LiveGrantProjection, validation CredentialValidation) (err error) {
	if input.Signer == nil || len(input.Fields) != 19 || validation.Issuer.Schema != "Grant" || validation.Issuer.Key == ([32]byte{}) {
		return CBORFailure("activation_grant_projection")
	}
	limit, err := SchemaByteLimit("Grant")
	if err != nil {
		return err
	}
	g.codec, err = NewSignedMapCodec("Grant", limit, limit)
	if err != nil {
		return err
	}
	g.signer, g.key = input.Signer, validation.Issuer.Key
	var complete [20]Field
	for i, f := range input.Fields {
		if f.Name == "signature" {
			return CBORFailure("projection_field")
		}
		complete[i] = f
	}
	var signature [64]byte
	complete[19] = Field{Name: "signature", Kind: ByteString, Bytes: signature[:]}
	wire, err := EncodeMap(g.codec.encoded, "Grant", complete[:])
	if err != nil {
		return err
	}
	g.document, err = g.codec.decoder.DecodeMap(wire, "Grant", DecodeContext{})
	clear(g.codec.encoded)
	if err != nil {
		return err
	}
	g.credential, err = detachCredentialDocument(g.document, "Grant", g.key, g.codec.signatureID, g.codec.encoded)
	if err != nil {
		return err
	}
	if err = g.credential.checkPermission(validation.Issuer); err != nil {
		return err
	}
	g.unsigned = make([]byte, limit)
	unsigned, err := g.document.copyWithout(g.unsigned, g.codec.signatureID)
	if err != nil {
		return err
	}
	g.unsigned = g.unsigned[:len(unsigned):len(unsigned)]
	message, err := g.codec.signingInput(g.document)
	if err != nil {
		return err
	}
	g.message = bytes.Clone(message)
	clear(g.codec.message)
	return nil
}

func (p *LiveActivationPlan) freezeTunnel(artifact *SignedMap, c *LiveTunnelActivationConfig) error {
	p.tunnel = &liveTunnelPlan{}
	t := p.tunnel
	var builder *liveGrantBuilder
	if c.Issuance != nil {
		for _, g := range c.Grants {
			if len(g.Fields) != 0 || g.Signer != nil {
				return CBORFailure("activation_grant_projection")
			}
		}
		var err error
		builder, err = newLiveGrantBuilder(artifact, p.fields, c, p.reservation)
		if err != nil {
			return err
		}
		defer builder.close()
	}
	for side := range t.grants {
		copy(t.bindings[side][:3], c.Bindings[:3])
		copy(t.bindings[side][3:], c.Bindings[3+2*side:5+2*side])
		input := c.Grants[side]
		if builder != nil {
			var err error
			input, err = builder.projection(side, c.Issuance[side])
			if err != nil {
				return err
			}
		}
		if err := t.grants[side].freeze(input, t.bindings[side][3]); err != nil {
			return err
		}
		g := &t.grants[side]
		if builder != nil && g.credential.scope != c.Issuance[side].Preparation.Scope {
			return CBORFailure("credential_grant_preparation")
		}
		if g.credential.scope.IssuedMS != p.fields.IssuedAt || g.credential.scope.ExpiresMS > p.fields.SessionEnd ||
			g.credential.scope.ExpiresMS < p.fields.ActivationEnd {
			return CBORFailure("activation_grant_projection")
		}
		closure, err := bindEndpointCredentials(Direction(side), artifact, p.fields.Winner.Index, c.Client, c.Server, nil, c.Relay, g, nil)
		if err != nil {
			return err
		}
		if err = closure.MatchActivation(p.authority); err != nil {
			return err
		}
		t.closures[side] = closure
		leg := &t.legs[side]
		leg.Grant = g.credential.facts.Digest
		leg.NotAfterMS = g.credential.scope.ExpiresMS
		root := g.document.Root()
		pairing, _ := root.Named("Grant", "pairing_id").ByteString()
		relay, _ := root.Named("Grant", "relay_identity_digest").ByteString()
		candidate := artifact.Field("candidates").Index(int(p.fields.Winner.Index))
		legName := "client_leg"
		if side == 1 {
			legName = "server_leg"
		}
		id, _ := candidate.Named("Candidate", legName).Named("Leg", "leg_id").ByteString()
		copy(leg.Pairing[:], pairing)
		copy(leg.RelayIdentity[:], relay)
		copy(leg.Leg[:], id)
		p.fields.GrantSigners[side] = g.key
		p.fields.GrantProjections[side] = sha256.Sum256(g.unsigned)
	}
	for _, field := range []string{"pairing_id", "parent_ref", "route_descriptor", "attempt_id", "identity_digests", "service", "audience", "relay_identity_digest"} {
		if !bytes.Equal(t.grants[0].document.Root().Named("Grant", field).Encoded(), t.grants[1].document.Root().Named("Grant", field).Encoded()) {
			return CBORFailure("activation_grant_projection")
		}
	}
	// Cross-leg duplicates must use one actual live owner, just as duplicate
	// dependencies in a selected endpoint closure do.
	for side, closure := range t.closures {
		for i, credential := range closure.credentials[:closure.count] {
			v := t.bindings[side][i]
			if v.Namespace == nil || v.Policy == nil {
				return CBORFailure("credential_namespace_owner")
			}
			if err := v.Namespace.reservation.CheckSameEnvironment(p.reservation); err != nil {
				return err
			}
			for earlierSide := 0; earlierSide <= side; earlierSide++ {
				end := t.closures[earlierSide].count
				if earlierSide == side {
					end = i
				}
				for j, previous := range t.closures[earlierSide].credentials[:end] {
					if credential.scope.Tenant == previous.scope.Tenant && credential.scope.Authority == previous.scope.Authority && v.Namespace != t.bindings[earlierSide][j].Namespace {
						return CBORFailure("credential_namespace_owner")
					}
				}
			}
		}
	}
	return t.checkCurrent(p.fields.SessionEnd)
}

func (p *LiveActivationPlan) ServerLeg() (LiveTunnelLegFields, error) {
	if p == nil {
		return LiveTunnelLegFields{}, CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.tunnel == nil {
		return LiveTunnelLegFields{}, CBORFailure("activation_owner")
	}
	if err := p.reservation.Check(); err != nil {
		return LiveTunnelLegFields{}, err
	}
	if err := p.shared.Check(); err != nil {
		return LiveTunnelLegFields{}, err
	}
	return p.tunnel.legs[1], nil
}

func (p *LiveActivationPlan) CheckTunnelPublication() error {
	if p == nil {
		return CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.tunnel == nil {
		return CBORFailure("activation_owner")
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	return p.tunnel.checkCurrent(p.fields.SessionEnd)
}

func (t *liveTunnelPlan) checkCurrent(end uint64) error {
	if t == nil {
		return nil
	}
	for side, closure := range t.closures {
		if closure == nil {
			return CBORFailure("activation_grant_projection")
		}
		if _, err := closure.CheckCurrent(t.bindings[side][:], end); err != nil {
			return err
		}
	}
	return nil
}

// issue signs exactly the already frozen document. No unsigned candidate is
// exposed as a SignedMap or as endpoint activation authority.
func (g *liveGrantPlan) issue(dst []byte, guard func() error) (int, error) {
	if len(dst) < len(g.document.Bytes()) {
		return 0, CBORFailure("configuration_capacity")
	}
	if err := guard(); err != nil {
		return 0, err
	}
	if !bytes.Equal(g.signer.PublicKey(), g.key[:]) {
		return 0, CBORFailure("signature_key_binding")
	}
	if err := guard(); err != nil {
		return 0, err
	}
	signature, err := g.signer.Sign(g.message)
	defer clear(signature)
	if err != nil {
		return 0, err
	}
	if err = guard(); err != nil {
		return 0, err
	}
	if !VerifyEd25519(signature, g.message, g.key[:]) {
		return 0, errSignatureGeneration
	}
	target, _ := g.document.Root().Field(g.codec.signatureID).ByteString()
	copy(target, signature)
	return copy(dst, g.document.Bytes()), nil
}

// CheckClientGrant binds read-only material to the original frozen local
// projection. It neither obtains the signer nor consumes an issuance right.
func (p *LiveActivationPlan) CheckClientGrant(grant *SignedMap) error {
	if p == nil || grant == nil {
		return CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.tunnel == nil {
		return CBORFailure("activation_owner")
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	g := &p.tunnel.grants[0]
	if grant.Key() != g.key {
		return CBORFailure("signature_key_binding")
	}
	if err := grant.MatchUnsignedProjection(g.unsigned); err != nil {
		return err
	}
	_, err := p.tunnel.closures[0].CheckCurrent(p.tunnel.bindings[0][:], p.fields.SessionEnd)
	return err
}

func (t *liveTunnelPlan) close() {
	if t == nil {
		return
	}
	for i := range t.grants {
		g := &t.grants[i]
		if g.document != nil {
			g.document.Release()
		}
		clear(g.unsigned)
		clear(g.message)
		if g.codec != nil {
			clear(g.codec.encoded)
			clear(g.codec.message)
		}
		*g = liveGrantPlan{}
	}
	t.closures = [2]*EndpointCredentials{}
	t.bindings = [2][5]CredentialValidation{}
}

// CopyProjections copies every original unsigned byte and frozen signer fact
// before TxA. It conveys no signing or dispatch authority.
func (p *LiveActivationPlan) CopyProjections(dst [3][]byte) (fields LiveActivationFields, sizes [3]int, err error) {
	if p == nil {
		return fields, sizes, CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.issued || p.active {
		return fields, sizes, CBORFailure("activation_owner")
	}
	if err = p.reservation.Check(); err != nil {
		return fields, sizes, err
	}
	if err = p.shared.Check(); err != nil {
		return fields, sizes, err
	}
	if len(dst[0]) < len(p.unsigned) {
		return fields, sizes, CBORFailure("configuration_capacity")
	}
	if p.tunnel != nil {
		for side := range p.tunnel.grants {
			if len(dst[1+side]) < len(p.tunnel.grants[side].unsigned) {
				return fields, sizes, CBORFailure("configuration_capacity")
			}
		}
	}
	sizes[0] = copy(dst[0], p.unsigned)
	if p.tunnel != nil {
		for side := range p.tunnel.grants {
			sizes[side+1] = copy(dst[side+1], p.tunnel.grants[side].unsigned)
		}
	}
	return p.fields, sizes, nil
}

// IssueMaterial produces private original TxB candidates together. The owner
// must persist all nonempty outputs atomically before any publication.
func (p *LiveActivationPlan) IssueMaterial(dst [3][]byte, guard func() error) ([3]int, error) {
	return p.issueMaterial(dst, guard, false)
}

// IsTunnel describes immutable plan geometry only; it grants no issue right.
func (p *LiveActivationPlan) IsTunnel() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fields.Tunnel
}
