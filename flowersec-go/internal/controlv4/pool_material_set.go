package controlv4

import (
	"encoding/binary"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

const poolMaterialNodes = 6 + sessionv4.MaxLeaseTunnelMaterials*5

// PoolTunnelMaterial is one original candidate/side pair. The signed Grant
// independently binds both selectors, its original route, identities and parent.
// The control bundle adds no authority and never changes the signed bytes.
type PoolTunnelMaterial struct {
	CandidateIndex          uint64
	Role                    protocolv4.Direction
	Grant, RelayCertificate []byte
}

// PoolTunnelTrust is installed independently of received material. The exact
// candidate and role lookup cannot be filled from a claimed signer or namespace.
type PoolTunnelTrust struct {
	CandidateIndex         uint64
	Role                   protocolv4.Direction
	GrantTrust, RelayTrust *protocolv4.NamespaceTrustStore
}

func validatePoolTunnelTrust(entries []PoolTunnelTrust) error {
	for i, entry := range entries {
		if entry.CandidateIndex >= 16 || entry.Role > protocolv4.ServerToClient || entry.GrantTrust == nil || entry.RelayTrust == nil ||
			i > 0 && !poolTunnelOrder(entries[i-1].CandidateIndex, entries[i-1].Role, entry.CandidateIndex, entry.Role) {
			return resourcev4.ErrConfiguration
		}
	}
	return nil
}

func poolTunnelOrder(left uint64, leftRole protocolv4.Direction, right uint64, rightRole protocolv4.Direction) bool {
	return left < right || left == right && leftRole < rightRole
}

func poolBytesSize(wire []byte) (int, error) {
	if len(wire) == 0 || len(wire) > 65535 {
		return 0, resourcev4.ErrConfiguration
	}
	n := len(wire) + 1
	if len(wire) >= 24 {
		n++
	}
	if len(wire) >= 256 {
		n++
	}
	return n, nil
}

// The caller has checked the full size before any output mutation.
func putPoolBytes(dst, wire []byte) int {
	n := 1
	switch {
	case len(wire) < 24:
		dst[0] = 0x40 | byte(len(wire))
	case len(wire) < 256:
		dst[0], dst[1], n = 0x58, byte(len(wire)), 2
	default:
		dst[0], n = 0x59, 3
		binary.BigEndian.PutUint16(dst[1:3], uint16(len(wire)))
	}
	return n + copy(dst[n:], wire)
}

func encodePoolMaterialSet(dst []byte, b PoolMaterialBundle) (int, error) {
	if len(b.Tunnels) > sessionv4.MaxLeaseTunnelMaterials || (len(b.Grant) == 0) != (len(b.RelayCertificate) == 0) ||
		len(b.Tunnels) != 0 && len(b.Grant) != 0 {
		return 0, resourcev4.ErrConfiguration
	}
	parts := [6][]byte{b.Artifact, b.Activation, b.ClientCertificate, b.ServerCertificate, b.Grant, b.RelayCertificate}
	count := 4
	if len(b.Grant) != 0 {
		count = 6
	}
	size := 1
	for _, wire := range parts[:count] {
		n, err := poolBytesSize(wire)
		if err != nil {
			return 0, err
		}
		size += n
	}
	if len(b.Tunnels) != 0 {
		size++
		if len(b.Tunnels) >= 24 {
			size++
		}
		for i, entry := range b.Tunnels {
			if entry.CandidateIndex >= 16 || entry.Role > protocolv4.ServerToClient || i > 0 &&
				!poolTunnelOrder(b.Tunnels[i-1].CandidateIndex, b.Tunnels[i-1].Role, entry.CandidateIndex, entry.Role) {
				return 0, resourcev4.ErrConfiguration
			}
			size += 3 // Array header and two shortest uint selectors.
			for _, wire := range [][]byte{entry.Grant, entry.RelayCertificate} {
				n, err := poolBytesSize(wire)
				if err != nil {
					return 0, err
				}
				size += n
			}
		}
	}
	if size > 65536 || size > len(dst) {
		return 0, resourcev4.ErrCapacity
	}
	dst[0] = 0x80 | byte(count)
	n := 1
	for _, wire := range parts[:count] {
		n += putPoolBytes(dst[n:], wire)
	}
	if len(b.Tunnels) != 0 {
		dst[0] = 0x85
		if len(b.Tunnels) < 24 {
			dst[n] = 0x80 | byte(len(b.Tunnels))
			n++
		} else {
			dst[n], dst[n+1] = 0x98, byte(len(b.Tunnels))
			n += 2
		}
		for _, entry := range b.Tunnels {
			dst[n], dst[n+1], dst[n+2] = 0x84, byte(entry.CandidateIndex), byte(entry.Role)
			n += 3
			n += putPoolBytes(dst[n:], entry.Grant)
			n += putPoolBytes(dst[n:], entry.RelayCertificate)
		}
	}
	return n, nil
}

func decodePoolMaterialSet(doc *protocolv4.Document, c PoolMaterialDecoderConfig) (PoolMaterialBundle, []sessionv4.ArtifactLeaseTunnelBytes, error) {
	fail := func() (PoolMaterialBundle, []sessionv4.ArtifactLeaseTunnelBytes, error) {
		return PoolMaterialBundle{}, nil, ErrResponse
	}
	root := doc.Root()
	wire := doc.Bytes()
	if len(wire) == 0 || wire[0] != 0x84 && wire[0] != 0x85 && wire[0] != 0x86 {
		return fail()
	}
	count := root.Len()
	if count < 4 || count > 6 {
		return fail()
	}
	var parts [6][]byte
	for i := 0; i < count; i++ {
		if count == 5 && i == 4 {
			break
		}
		var ok bool
		parts[i], ok = root.Index(i).ByteString()
		if !ok || len(parts[i]) == 0 || len(parts[i]) > 65535 {
			return fail()
		}
	}
	bundle := PoolMaterialBundle{Artifact: parts[0], Activation: parts[1], ClientCertificate: parts[2], ServerCertificate: parts[3], Grant: parts[4], RelayCertificate: parts[5]}
	if count != 5 {
		return bundle, nil, nil
	}
	set := root.Index(4)
	encoded := set.Encoded()
	if len(encoded) == 0 || encoded[0]>>5 != 4 || set.Len() == 0 || set.Len() > sessionv4.MaxLeaseTunnelMaterials {
		return fail()
	}
	var selected [16]sessionv4.ArtifactLeaseTunnelBytes
	n := 0
	var previousIndex uint64
	var previousRole protocolv4.Direction
	for i := 0; i < set.Len(); i++ {
		item := set.Index(i)
		encoded := item.Encoded()
		if len(encoded) == 0 || encoded[0] != 0x84 || item.Len() != 4 {
			return fail()
		}
		index, indexOK := item.Index(0).Uint()
		role, roleOK := item.Index(1).Uint()
		grant, grantOK := item.Index(2).ByteString()
		relay, relayOK := item.Index(3).ByteString()
		if !indexOK || index >= 16 || !roleOK || role > 1 || !grantOK || !relayOK || len(grant) == 0 || len(relay) == 0 ||
			len(grant) > 65535 || len(relay) > 65535 || i > 0 && !poolTunnelOrder(previousIndex, previousRole, index, protocolv4.Direction(role)) {
			return fail()
		}
		previousIndex, previousRole = index, protocolv4.Direction(role)
		if previousRole != c.Role {
			continue // The remote role's roots are not local endpoint dependencies.
		}
		if n >= max(1, int(c.MaxTunnelMaterials)) {
			return fail()
		}
		entry := sessionv4.ArtifactLeaseTunnelBytes{CandidateIndex: index, Role: previousRole, Grant: grant, RelayCertificate: relay}
		for _, binding := range c.TunnelTrust {
			if binding.CandidateIndex == index && binding.Role == previousRole {
				entry.GrantTrust, entry.RelayTrust = binding.GrantTrust, binding.RelayTrust
				break
			}
		}
		if entry.GrantTrust == nil || entry.RelayTrust == nil {
			return fail()
		}
		selected[n], n = entry, n+1
	}
	if n == 0 {
		return fail()
	}
	return bundle, selected[:n:n], nil
}
