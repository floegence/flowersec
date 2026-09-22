package protocolv4

import (
	"bytes"
	"sync"
	"unsafe"
)

// HandshakeIdentity is a detached projection of the exact bound certificate.
// It does not replace its issuer/current trust, revocation or possession checks.
type HandshakeIdentity struct {
	Digest, EdPublic [32]byte
	DHPublic         [65]byte
	DHBytes          int
	ExpiresAtMS      uint64
}

// HandshakeMaterial contains sensitive owned bytes. Its private snapshot can
// only be constructed from the complete original admission and certificate
// binding. Read copies into the caller's reserved FSB/FSA buffers; Close erases
// the PSK and source bytes. It grants no dispatch/activation/Session authority.
type HandshakeMaterial struct {
	mu       sync.Mutex
	closed   bool
	facts    HandshakeFacts
	fsb, fsa []byte
}

type HandshakeFacts struct {
	Profile                     string
	Session                     ArtifactSessionParameters
	PSK                         [32]byte
	Context, Admission          [32]byte
	Client, Server              HandshakeIdentity
	Features, SessionNotAfterMS uint64
}

func HandshakeMaterialBackingBytes() (uint64, error) {
	fsb, err := SchemaByteLimit("FSB4")
	if err != nil {
		return 0, err
	}
	fsa, err := SchemaByteLimit("FSA4")
	if err != nil {
		return 0, err
	}
	// The two profile text values are bounded by the original Artifact cap.
	artifact, err := SchemaByteLimit("Artifact")
	if err != nil {
		return 0, err
	}
	return uint64(fsb+fsa+artifact) + uint64(unsafe.Sizeof(HandshakeMaterial{})), nil
}

func (h *HelloBinding) BindHandshakeMaterial(artifact *SignedMap, activation *ActivationBinding, client, server, fsb, fsa *SignedMap) (*HandshakeMaterial, error) {
	if h == nil || artifact == nil || artifact.codec.schema != "Artifact" {
		return nil, CBORFailure("handshake_material")
	}
	response, err := h.MatchFSA(fsa, server, activation, fsb, client)
	if err != nil {
		return nil, err
	}
	if !response.Admitted {
		return nil, CBORFailure("handshake_rejected")
	}
	material := &HandshakeMaterial{}
	success := false
	defer func() {
		if !success {
			material.Close()
		}
	}()
	err = func() error {
		a := artifact.codec
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.current != artifact {
			return CBORFailure("artifact_owner")
		}
		digest, err := fullMapDigest("artifact_digest", "Artifact", artifact.document.Bytes())
		if err != nil {
			return err
		}
		if digest != h.artifact {
			return CBORFailure("handshake_material")
		}
		parent := func(name string) Value { return artifact.document.Root().Named("Artifact", name) }
		material.facts.Profile, _ = parent("crypto_profile_id").Text()
		material.facts.Session, err = artifact.sessionParametersLocked()
		if err != nil {
			return err
		}
		psk, _ := parent("e2ee_psk").ByteString()
		copy(material.facts.PSK[:], psk)
		material.facts.SessionNotAfterMS, _ = parent("session_not_after_ms").Uint()
		return nil
	}()
	if err != nil {
		return nil, err
	}
	material.facts.Context = h.transport
	material.facts.Admission = response.AdmissionBinding
	material.facts.Features = h.features
	_, activationEnd := activation.Deadlines()
	material.facts.SessionNotAfterMS = min(material.facts.SessionNotAfterMS, activationEnd)
	for _, entry := range []struct {
		certificate *SignedMap
		role        Direction
		want        [32]byte
		out         *HandshakeIdentity
	}{
		{client, ClientToServer, h.clientIdentity, &material.facts.Client}, {server, ServerToClient, h.serverIdentity, &material.facts.Server},
	} {
		err := func() error {
			c := entry.certificate.codec
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.current != entry.certificate {
				return CBORFailure("admission_owner")
			}
			digest, err := fullMapDigest("certificate_digest", "IdentityCertificate", entry.certificate.document.Bytes())
			if err != nil {
				return err
			}
			if digest != entry.want {
				return CBORFailure("admission_identity_binding")
			}
			root := entry.certificate.document.Root()
			role, _ := root.Named("IdentityCertificate", "role").Uint()
			profile, _ := root.Named("IdentityCertificate", "crypto_profile_id").Text()
			if role != uint64(entry.role) || profile != h.profile {
				return CBORFailure("admission_identity_binding")
			}
			spec, err := Profile(profile)
			if err != nil {
				return err
			}
			key := root.Named("IdentityCertificate", "noise_static_public_key")
			algorithm, _ := key.Named("NoiseStaticPublicKey", "algorithm").Uint()
			public, _ := key.Named("NoiseStaticPublicKey", "public_key_bytes").ByteString()
			if algorithm != uint64(spec.DHAlgorithm) || len(public) != spec.DHPublicBytes {
				return CBORFailure("handshake_identity_key")
			}
			entry.out.Digest = digest
			entry.out.DHBytes = copy(entry.out.DHPublic[:], public)
			ed, _ := root.Named("IdentityCertificate", "ed25519_public_key").ByteString()
			copy(entry.out.EdPublic[:], ed)
			entry.out.ExpiresAtMS, _ = root.Named("IdentityCertificate", "expires_at_ms").Uint()
			return nil
		}()
		if err != nil {
			return nil, err
		}
		material.facts.SessionNotAfterMS = min(material.facts.SessionNotAfterMS, entry.out.ExpiresAtMS)
	}
	for _, entry := range []struct {
		source *SignedMap
		out    *[]byte
	}{{fsb, &material.fsb}, {fsa, &material.fsa}} {
		c := entry.source.codec
		c.mu.Lock()
		if c.current != entry.source {
			c.mu.Unlock()
			return nil, CBORFailure("admission_owner")
		}
		*entry.out = bytes.Clone(entry.source.document.Bytes())
		c.mu.Unlock()
	}
	success = true
	return material, nil
}

// Read returns only copies. The caller must clear the returned PSK after
// constructing the one original crypto owner; borrowed source maps are unused.
func (m *HandshakeMaterial) Read(fsb, fsa []byte) (facts HandshakeFacts, fsbBytes, fsaBytes int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return facts, 0, 0, CBORFailure("handshake_material_closed")
	}
	if len(fsb) < len(m.fsb) || len(fsa) < len(m.fsa) {
		return facts, 0, 0, CBORFailure("encoder_capacity")
	}
	return m.facts, copy(fsb, m.fsb), copy(fsa, m.fsa), nil
}

func (m *HandshakeMaterial) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	clear(m.facts.PSK[:])
	clear(m.fsb)
	clear(m.fsa)
	m.fsb, m.fsa = nil, nil
}
