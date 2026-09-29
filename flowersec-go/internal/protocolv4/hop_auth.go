package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sync"
)

// HopSenderRole identifies the authenticated sender of a HOP_AUTH HELLO.
// Endpoint HELLOs carry the issued Grant; relay HELLOs deliberately do not.
type HopSenderRole string

const (
	HopSenderEndpoint HopSenderRole = "endpoint"
	HopSenderRelay    HopSenderRole = "relay"
)

type HopAuthPhase uint8

const (
	HopAuthHelloPhase         HopAuthPhase = 0
	HopAuthEndpointProofPhase HopAuthPhase = 1
	HopAuthRelayProofPhase    HopAuthPhase = 2
)

var (
	ErrHopAuthPhase   = errors.New("protocolv4: invalid hop-auth phase")
	ErrHopAuthContext = errors.New("protocolv4: invalid hop-auth context")
	ErrHopAuthProof   = errors.New("protocolv4: invalid hop-auth proof")
	ErrHopAuthStage   = errors.New("protocolv4: hop-auth requires activated tunnel preauth")
)

// HopChallengeContext is the exact challenge context committed by
// grant_possession. Incarnations, challenges and leg identity are all
// independent inputs; a caller cannot replace one with a transport digest.
type HopChallengeContext struct {
	DialerIncarnation   [16]byte
	ListenerIncarnation [16]byte
	LegID               [16]byte
	DialerRole          uint8
	ListenerRole        uint8
	DialerChallenge     [32]byte
	ListenerChallenge   [32]byte
}

func (c HopChallengeContext) valid() error {
	if c.DialerIncarnation == ([16]byte{}) || c.ListenerIncarnation == ([16]byte{}) ||
		c.DialerChallenge == ([32]byte{}) || c.ListenerChallenge == ([32]byte{}) {
		return ErrHopAuthContext
	}
	if c.DialerRole > 2 || c.ListenerRole > 2 {
		return ErrHopAuthContext
	}
	allowed := [][2]uint8{{0, 2}, {1, 2}, {2, 0}, {2, 1}}
	for _, pair := range allowed {
		if c.DialerRole == pair[0] && c.ListenerRole == pair[1] {
			return nil
		}
	}
	return ErrHopAuthContext
}

// EncodeHopChallengeContext emits the registry's canonical challenge map.
// Keeping this helper beside the possession domain prevents callers from
// inventing a second serialization for the bytes covered by the signature.
func EncodeHopChallengeContext(dst []byte, c HopChallengeContext) ([]byte, error) {
	if err := c.valid(); err != nil {
		return nil, err
	}
	return EncodeMap(dst, "HopChallengeContext", []Field{
		{Name: "dialer_incarnation", Kind: ByteString, Bytes: c.DialerIncarnation[:]},
		{Name: "listener_incarnation", Kind: ByteString, Bytes: c.ListenerIncarnation[:]},
		{Name: "leg_id", Kind: ByteString, Bytes: c.LegID[:]},
		{Name: "dialer_role", Number: uint64(c.DialerRole)},
		{Name: "listener_role", Number: uint64(c.ListenerRole)},
		{Name: "dialer_challenge", Kind: ByteString, Bytes: c.DialerChallenge[:]},
		{Name: "listener_challenge", Kind: ByteString, Bytes: c.ListenerChallenge[:]},
	})
}

func DecodeHopChallengeContext(decoder *Decoder, wire []byte) (HopChallengeContext, error) {
	if decoder == nil {
		return HopChallengeContext{}, ErrHopAuthContext
	}
	doc, err := decoder.DecodeMap(wire, "HopChallengeContext", DecodeContext{})
	if err != nil {
		return HopChallengeContext{}, err
	}
	defer doc.Release()
	root := doc.Root()
	var out HopChallengeContext
	for name, dst := range map[string][]byte{
		"dialer_incarnation":   out.DialerIncarnation[:],
		"listener_incarnation": out.ListenerIncarnation[:],
		"leg_id":               out.LegID[:],
		"dialer_challenge":     out.DialerChallenge[:],
		"listener_challenge":   out.ListenerChallenge[:],
	} {
		value, ok := root.Named("HopChallengeContext", name).ByteString()
		if !ok || len(value) != len(dst) {
			return HopChallengeContext{}, ErrHopAuthContext
		}
		copy(dst, value)
	}
	for name, dst := range map[string]*uint8{"dialer_role": &out.DialerRole, "listener_role": &out.ListenerRole} {
		value, ok := root.Named("HopChallengeContext", name).Uint()
		if !ok || value > 2 {
			return HopChallengeContext{}, ErrHopAuthContext
		}
		*dst = uint8(value)
	}
	if err := out.valid(); err != nil {
		return HopChallengeContext{}, err
	}
	return out, nil
}

// HopAuthHello is a decoded HOP_AUTH_HELLO. Grant and certificate are copied
// from the decoder document and remain independent of its backing arena.
type HopAuthHello struct {
	SenderRole          HopSenderRole
	LocalIncarnation    [16]byte
	LocalChallenge      [32]byte
	Grant               []byte
	IdentityCertificate []byte
}

// HopAuthProof is one of the two fixed 64-byte proof variants.
type HopAuthProof struct {
	Phase HopAuthPhase
	Proof [ed25519.SignatureSize]byte
}

// HopAuthFrameSpec returns the registry schema and size for a HOP_AUTH
// variant. The frame is valid only when the carrier has already entered the
// tunnel activated-preauth state; direct and post-READY callers are rejected.
func HopAuthFrameSpec(activatedPreauth bool, sender Direction, senderRole HopSenderRole, phase HopAuthPhase) (InitialFrameSpec, error) {
	if !activatedPreauth || sender > ServerToClient {
		return InitialFrameSpec{}, ErrHopAuthStage
	}
	if senderRole != HopSenderEndpoint && senderRole != HopSenderRelay {
		return InitialFrameSpec{}, ErrHopAuthContext
	}
	var schema string
	switch phase {
	case HopAuthHelloPhase:
		schema = "HOP_AUTH_HELLO"
	case HopAuthEndpointProofPhase:
		if senderRole != HopSenderEndpoint {
			return InitialFrameSpec{}, ErrHopAuthContext
		}
		schema = "HOP_AUTH_ENDPOINT_PROOF"
	case HopAuthRelayProofPhase:
		if senderRole != HopSenderRelay {
			return InitialFrameSpec{}, ErrHopAuthContext
		}
		schema = "HOP_AUTH_RELAY_PROOF"
	default:
		return InitialFrameSpec{}, ErrHopAuthPhase
	}
	maximum, err := SchemaByteLimit(schema)
	if err != nil {
		return InitialFrameSpec{}, err
	}
	return InitialFrameSpec{Schema: schema, Maximum: maximum}, nil
}

// InitialHopAuth rejects HOP_AUTH for direct initial exchanges. The explicit
// context argument prevents a frame-type value alone from granting tunnel
// pre-auth privileges.
func InitialHopAuth(activatedPreauth bool, sender Direction, senderRole HopSenderRole, phase HopAuthPhase) (InitialFrameSpec, error) {
	return HopAuthFrameSpec(activatedPreauth, sender, senderRole, phase)
}

func (h HopAuthHello) fields() ([]Field, error) {
	if h.SenderRole != HopSenderEndpoint && h.SenderRole != HopSenderRelay {
		return nil, ErrHopAuthContext
	}
	if h.LocalIncarnation == ([16]byte{}) || h.LocalChallenge == ([32]byte{}) || len(h.IdentityCertificate) == 0 || len(h.IdentityCertificate) > 8192 {
		return nil, ErrHopAuthContext
	}
	fields := []Field{
		{Name: "phase", Number: uint64(HopAuthHelloPhase)},
		{Name: "local_incarnation", Kind: ByteString, Bytes: h.LocalIncarnation[:]},
		{Name: "local_challenge", Kind: ByteString, Bytes: h.LocalChallenge[:]},
		{Name: "identity_certificate", Kind: ByteString, Bytes: h.IdentityCertificate},
	}
	if h.SenderRole == HopSenderEndpoint {
		if len(h.Grant) == 0 {
			return nil, ErrHopAuthContext
		}
		fields = append(fields, Field{Name: "grant", Kind: ByteString, Bytes: h.Grant})
	} else if len(h.Grant) != 0 {
		return nil, ErrHopAuthContext
	}
	return fields, nil
}

// EncodeHopAuthHello encodes a canonical HOP_AUTH_HELLO into caller-owned
// storage. Nested Grant and IdentityCertificate bytes are validated as their
// registered encoded schemas before they are emitted.
func EncodeHopAuthHello(dst []byte, h HopAuthHello) ([]byte, error) {
	fields, err := h.fields()
	if err != nil {
		return nil, err
	}
	if err = validateHopNested(h.SenderRole, h.Grant, h.IdentityCertificate); err != nil {
		return nil, err
	}
	return EncodeMap(dst, "HOP_AUTH_HELLO", fields)
}

func validateHopNested(role HopSenderRole, grant, certificate []byte) error {
	if len(certificate) == 0 || len(certificate) > 8192 {
		return ErrHopAuthContext
	}
	dec, err := NewDecoder(max(len(certificate), 1), 256)
	if err != nil {
		return err
	}
	doc, err := dec.DecodeMap(certificate, "IdentityCertificate", DecodeContext{})
	if err != nil {
		return err
	}
	certRole, ok := doc.Root().Named("IdentityCertificate", "role").Uint()
	doc.Release()
	if !ok {
		return ErrHopAuthContext
	}
	if role == HopSenderRelay {
		if certRole != 2 || len(grant) != 0 {
			return ErrHopAuthContext
		}
		return nil
	}
	if certRole > 1 || len(grant) == 0 {
		return ErrHopAuthContext
	}
	dec, err = NewDecoder(max(len(grant), 1), 512)
	if err != nil {
		return err
	}
	g, err := dec.DecodeMap(grant, "Grant", DecodeContext{})
	if err != nil {
		return err
	}
	g.Release()
	return nil
}

// DecodeHopAuthHello validates both the fixed schema and the role-dependent
// grant/certificate rules. The returned byte slices are owned copies.
func DecodeHopAuthHello(decoder *Decoder, wire []byte, senderRole HopSenderRole) (HopAuthHello, error) {
	if decoder == nil || (senderRole != HopSenderEndpoint && senderRole != HopSenderRelay) {
		return HopAuthHello{}, ErrHopAuthContext
	}
	doc, err := decoder.DecodeMap(wire, "HOP_AUTH_HELLO", DecodeContext{Selectors: map[string]string{"hop_sender_role": string(senderRole)}})
	if err != nil {
		return HopAuthHello{}, err
	}
	defer doc.Release()
	root := doc.Root()
	phase, ok := root.Named("HOP_AUTH_HELLO", "phase").Uint()
	if !ok || phase != uint64(HopAuthHelloPhase) {
		return HopAuthHello{}, ErrHopAuthPhase
	}
	var out HopAuthHello
	out.SenderRole = senderRole
	inc, ok := root.Named("HOP_AUTH_HELLO", "local_incarnation").ByteString()
	if !ok || len(inc) != len(out.LocalIncarnation) {
		return HopAuthHello{}, ErrHopAuthContext
	}
	copy(out.LocalIncarnation[:], inc)
	challenge, ok := root.Named("HOP_AUTH_HELLO", "local_challenge").ByteString()
	if !ok || len(challenge) != len(out.LocalChallenge) {
		return HopAuthHello{}, ErrHopAuthContext
	}
	copy(out.LocalChallenge[:], challenge)
	cert, ok := root.Named("HOP_AUTH_HELLO", "identity_certificate").ByteString()
	if !ok {
		return HopAuthHello{}, ErrHopAuthContext
	}
	out.IdentityCertificate = bytes.Clone(cert)
	if grant, present := root.Named("HOP_AUTH_HELLO", "grant").ByteString(); present {
		out.Grant = bytes.Clone(grant)
	}
	if err := validateHopNested(senderRole, out.Grant, out.IdentityCertificate); err != nil {
		return HopAuthHello{}, err
	}
	return out, nil
}

func (p HopAuthProof) schema() (string, error) {
	switch p.Phase {
	case HopAuthEndpointProofPhase:
		return "HOP_AUTH_ENDPOINT_PROOF", nil
	case HopAuthRelayProofPhase:
		return "HOP_AUTH_RELAY_PROOF", nil
	default:
		return "", ErrHopAuthPhase
	}
}

func EncodeHopAuthProof(dst []byte, p HopAuthProof) ([]byte, error) {
	schema, err := p.schema()
	if err != nil {
		return nil, err
	}
	return EncodeMap(dst, schema, []Field{{Name: "phase", Number: uint64(p.Phase)}, {Name: "proof", Kind: ByteString, Bytes: p.Proof[:]}})
}

func DecodeHopAuthProof(decoder *Decoder, wire []byte, phase HopAuthPhase) (HopAuthProof, error) {
	if decoder == nil {
		return HopAuthProof{}, ErrHopAuthContext
	}
	schema, err := (HopAuthProof{Phase: phase}).schema()
	if err != nil {
		return HopAuthProof{}, err
	}
	doc, err := decoder.DecodeMap(wire, schema, DecodeContext{})
	if err != nil {
		return HopAuthProof{}, err
	}
	defer doc.Release()
	b, ok := doc.Root().Named(schema, "proof").ByteString()
	if !ok || len(b) != ed25519.SignatureSize {
		return HopAuthProof{}, ErrHopAuthProof
	}
	var out HopAuthProof
	out.Phase = phase
	copy(out.Proof[:], b)
	return out, nil
}

// GrantPossessionInput contains the exact values consumed by the registry's
// grant_possession domain. HopContext must be canonical HopChallengeContext
// bytes, not an application-defined serialization.
type GrantPossessionInput struct {
	GrantDigest [32]byte
	RouteDigest [32]byte
	LegID       [16]byte
	PairingID   [16]byte
	HopContext  []byte
	Role        uint8
}

var grantPossessionDomain = sync.OnceValues(func() ([]byte, error) {
	var domains []struct {
		Name, Operation string
		Label           string `json:"label_bytes"`
	}
	if err := json.Unmarshal([]byte(DomainRegistryJSON), &domains); err != nil {
		return nil, CBORFailure("registry_unresolved")
	}
	for _, domain := range domains {
		if domain.Name == "grant_possession" && domain.Operation == "ed25519" {
			label, err := hex.DecodeString(domain.Label)
			if err != nil || len(label) == 0 || label[len(label)-1] != 0 {
				return nil, CBORFailure("registry_unresolved")
			}
			return label, nil
		}
	}
	return nil, CBORFailure("registry_unresolved")
})

func (in GrantPossessionInput) validate() error {
	if in.Role > 2 || len(in.HopContext) != 129 {
		return ErrHopAuthContext
	}
	if uint64(len(in.HopContext)) > math.MaxUint32 {
		return ErrHopAuthContext
	}
	dec, err := NewDecoder(len(in.HopContext), 128)
	if err != nil {
		return err
	}
	context, err := DecodeHopChallengeContext(dec, in.HopContext)
	if err != nil {
		return err
	}
	if context.LegID != in.LegID {
		return ErrHopAuthContext
	}
	if in.Role != context.DialerRole && in.Role != context.ListenerRole {
		return ErrHopAuthContext
	}
	return nil
}

func grantPossessionMessage(in GrantPossessionInput) ([]byte, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	if uint64(len(in.HopContext)) > math.MaxUint32 {
		return nil, ErrHopAuthContext
	}
	label, err := grantPossessionDomain()
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(label)+4+32+4+32+4+16+4+16+4+len(in.HopContext)+1)
	message = append(message, label...)
	appendLP := func(value []byte) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		message = append(message, size[:]...)
		message = append(message, value...)
	}
	appendLP(in.GrantDigest[:])
	appendLP(in.RouteDigest[:])
	appendLP(in.LegID[:])
	appendLP(in.PairingID[:])
	appendLP(in.HopContext)
	message = append(message, in.Role)
	return message, nil
}

// GrantPossessionMessage returns a copy of the registry-defined signing
// message, including its domain label and NUL. Hardware signers sign these
// exact bytes without applying a second domain prefix.
func GrantPossessionMessage(in GrantPossessionInput) ([]byte, error) {
	return grantPossessionMessage(in)
}

func SignGrantPossession(in GrantPossessionInput, private ed25519.PrivateKey) ([ed25519.SignatureSize]byte, error) {
	var out [ed25519.SignatureSize]byte
	if len(private) != ed25519.PrivateKeySize {
		return out, ErrHopAuthProof
	}
	message, err := grantPossessionMessage(in)
	if err != nil {
		return out, err
	}
	copy(out[:], ed25519.Sign(private, message))
	clear(message)
	return out, nil
}

func VerifyGrantPossession(in GrantPossessionInput, public [ed25519.PublicKeySize]byte, proof [ed25519.SignatureSize]byte) error {
	message, err := grantPossessionMessage(in)
	if err != nil {
		return err
	}
	ok := VerifyEd25519(proof[:], message, public[:])
	clear(message)
	if !ok {
		return ErrHopAuthProof
	}
	return nil
}
