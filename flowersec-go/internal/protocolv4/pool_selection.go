package protocolv4

import (
	"bytes"
	"sync"
	"unsafe"
)

// PoolMember is detached public selection data. It holds no Artifact/PSK,
// proof, grant, decoder alias or activation capability.
type PoolMember struct {
	Index       uint64
	CandidateID [16]byte
	RouteDigest [32]byte
}

// MatchCandidateRoute binds an already decoded public route to the original
// signed selection before credential-free preparation. It grants no authority.
func (d *Document) MatchCandidateRoute(member PoolMember) error {
	if d == nil || d.schema != "Route" || member.Index >= 16 {
		return CBORFailure("carrier_binding_invalid")
	}
	id, ok := d.Root().Named("Route", "candidate_id").ByteString()
	if !ok || len(id) != 16 || [16]byte(id) != member.CandidateID {
		return CBORFailure("carrier_binding_invalid")
	}
	digest, err := fullMapDigest("route_digest", "Route", d.Bytes())
	if err != nil {
		return err
	}
	if digest != member.RouteDigest {
		return CBORFailure("carrier_binding_invalid")
	}
	return nil
}

// PoolSelectionWorkspace reserves all route/array/set and member backing before
// deriving a selection. It has one retained result and no dynamic queue/growth.
// The caller's declared caps must cover its signed Artifact before any spend.
type PoolSelectionWorkspace struct {
	mu                    sync.Mutex
	route, array, encoded []byte
	members               []PoolMember
	indices               []uint64
	current               *PoolSelection
}

type PoolSelection struct {
	workspace                                          *PoolSelectionWorkspace
	count, size                                        int
	artifactDigest, candidateSetDigest, routeSetDigest [32]byte
}

// PoolSelectionBackingBytes includes the retained result and all scratch/member
// storage. Issuance/Prepare must reserve it before choosing or spending a lease.
func PoolSelectionBackingBytes(routeBytes, selectionBytes int) (uint64, error) {
	maximum, err := FieldItemLimit("PoolSelectionRef", "candidate_indices")
	if err != nil {
		return 0, err
	}
	if routeBytes <= 0 || selectionBytes <= 0 || uint64(routeBytes) > uint64(MaxPayloadLength) || uint64(selectionBytes) > uint64(MaxPayloadLength) {
		return 0, CBORFailure("configuration_capacity")
	}
	return uint64(routeBytes) + 2*uint64(selectionBytes) + uint64(maximum)*(uint64(unsafe.Sizeof(PoolMember{}))+8) + uint64(unsafe.Sizeof(PoolSelectionWorkspace{})) + uint64(unsafe.Sizeof(PoolSelection{})), nil
}

func NewPoolSelectionWorkspace(routeBytes, selectionBytes int) (*PoolSelectionWorkspace, error) {
	if _, err := PoolSelectionBackingBytes(routeBytes, selectionBytes); err != nil {
		return nil, err
	}
	maximum, err := FieldItemLimit("PoolSelectionRef", "candidate_indices")
	if err != nil {
		return nil, err
	}
	return &PoolSelectionWorkspace{route: make([]byte, routeBytes), array: make([]byte, selectionBytes), encoded: make([]byte, selectionBytes), members: make([]PoolMember, maximum), indices: make([]uint64, maximum)}, nil
}

// projectCandidate preserves exact canonical field values and uses only the
// generated candidate_route field-name mapping. No priority, namespace list,
// secret or duplicate route definition enters the public Route digest.
func projectCandidate(dst []byte, candidate Value) ([]byte, error) {
	if !candidate.valid() {
		return nil, CBORFailure("document_released")
	}
	r := candidate.document.decoder.registry
	projection, ok := r.MapProjections["candidate_route"]
	if !ok || projection.Source != "Candidate" || projection.Target != "Route" || len(projection.Fields) > 128 {
		return nil, CBORFailure("projection_unresolved")
	}
	var fields [128]Field
	count := 0
	for _, name := range projection.Fields {
		v := candidate.Named(projection.Source, name)
		if !v.valid() {
			continue
		}
		f := Field{Name: name}
		n := v.document.decoder.nodes[v.index]
		switch n.major {
		case 0:
			f.Number = n.n
		case 2:
			f.Kind = ByteString
			f.Bytes, _ = v.ByteString()
		case 5:
			f.Kind, f.Bytes = EncodedMap, v.Encoded()
		default:
			return nil, CBORFailure("projection_field")
		}
		fields[count] = f
		count++
	}
	return EncodeMap(dst, projection.Target, fields[:count])
}

// CopyCandidateRoute derives the whole route for one original Artifact index.
// It establishes byte binding only; trusted issuer/current policy and physical
// provider eligibility still belong to the connection's admission owner.
func (m *SignedMap) CopyCandidateRoute(index uint64, dst []byte) ([]byte, [32]byte, error) {
	c := m.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != m || c.schema != "Artifact" {
		return nil, [32]byte{}, CBORFailure("artifact_owner")
	}
	candidates := m.document.Root().Named("Artifact", "candidates")
	if index >= uint64(candidates.Len()) {
		return nil, [32]byte{}, CBORFailure("pool_index_membership")
	}
	wire, err := projectCandidate(dst, candidates.Index(int(index)))
	if err != nil {
		return nil, [32]byte{}, err
	}
	digest, err := fullMapDigest("route_digest", "Route", wire)
	return wire, digest, err
}

func (w *PoolSelectionWorkspace) clear() {
	clear(w.route)
	clear(w.array)
	clear(w.encoded)
	clear(w.members)
	clear(w.indices)
}

// Derive requires a signature-checked original Artifact. Its original index
// sequence is checked without sorting, deduplicating or merging equal routes.
// Result retention is explicit; the Artifact can be released after this call.
func (w *PoolSelectionWorkspace) Derive(artifact *SignedMap, indices []uint64) (_ *PoolSelection, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if artifact == nil {
		return nil, CBORFailure("artifact_owner")
	}
	c := artifact.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	return w.deriveLocked(artifact, indices)
}

// Caller holds both the workspace and original Artifact codec.
func (w *PoolSelectionWorkspace) deriveLocked(artifact *SignedMap, indices []uint64) (_ *PoolSelection, err error) {
	if w.current != nil {
		return nil, CBORFailure("decoder_busy")
	}
	if artifact == nil || len(indices) == 0 || len(indices) > len(w.members) {
		return nil, CBORFailure("array_length")
	}
	defer func() {
		if err != nil {
			w.clear()
		}
	}()
	c := artifact.codec
	if c.current != artifact || c.schema != "Artifact" {
		return nil, CBORFailure("artifact_owner")
	}
	candidates := artifact.document.Root().Named("Artifact", "candidates")
	offset, err := cborHead(w.array, 4, uint64(len(indices)))
	if err != nil {
		return nil, err
	}
	for i, index := range indices {
		if i > 0 && indices[i-1] >= index {
			return nil, CBORFailure("pool_index_order")
		}
		if index >= uint64(candidates.Len()) {
			return nil, CBORFailure("pool_index_membership")
		}
		candidate := candidates.Index(int(index))
		route, err := projectCandidate(w.route, candidate)
		if err != nil {
			return nil, err
		}
		digest, err := fullMapDigest("route_digest", "Route", route)
		if err != nil {
			return nil, err
		}
		id, ok := candidate.Named("Candidate", "candidate_id").ByteString()
		if !ok || len(id) != 16 {
			return nil, CBORFailure("pool_candidate_id")
		}
		member := PoolMember{Index: index, CandidateID: [16]byte(id), RouteDigest: digest}
		for _, previous := range w.members[:i] {
			if previous.CandidateID == member.CandidateID {
				return nil, CBORFailure("pool_candidate_id")
			}
		}
		w.members[i] = member
		entry, err := EncodeMap(w.array[offset:], "PoolRouteRef", []Field{{Name: "candidate_index", Number: index}, {Name: "candidate_id", Kind: ByteString, Bytes: member.CandidateID[:]}, {Name: "route_digest", Kind: ByteString, Bytes: member.RouteDigest[:]}})
		if err != nil {
			return nil, err
		}
		offset += len(entry)
	}
	digest, err := fullMapDigest("artifact_digest", "Artifact", artifact.document.Bytes())
	if err != nil {
		return nil, err
	}
	encoded, err := EncodeMap(w.encoded, "PoolSelectionSet", []Field{{Name: "artifact_digest", Kind: ByteString, Bytes: digest[:]}, {Name: "entries", Kind: EncodedArray, Bytes: w.array[:offset]}})
	if err != nil {
		return nil, err
	}
	candidateDigest, err := fullMapDigest("candidate_set_digest", "PoolSelectionSet", encoded)
	if err != nil {
		return nil, err
	}
	routeDigest, err := fullMapDigest("route_set_digest", "PoolSelectionSet", encoded)
	if err != nil {
		return nil, err
	}
	clear(w.route)
	clear(w.array)
	p := &PoolSelection{workspace: w, count: len(indices), size: len(encoded), artifactDigest: digest, candidateSetDigest: candidateDigest, routeSetDigest: routeDigest}
	w.current = p
	return p, nil
}

// MatchProof is exclusively the immutable preauthorized_pool path. A live
// authority proof cannot be reinterpreted as a pool or used as a fallback.
// This checks the set reference, not trust, attempt-budget consumption or once.
func (p *PoolSelection) MatchProof(proof *SignedMap) error {
	w := p.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != p || proof == nil {
		return CBORFailure("pool_owner")
	}
	c := proof.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	return p.matchProofLocked(proof)
}

// Caller holds both the selection workspace and original proof codec.
func (p *PoolSelection) matchProofLocked(proof *SignedMap) error {
	w, c := p.workspace, proof.codec
	if c.current != proof || c.schema != "ActivationAuthorization" || proof.activationSourceProfile != "preauthorized_pool" {
		return CBORFailure("activation_owner")
	}
	root := proof.document.Root()
	reference := root.Named(c.schema, "candidate_selection")
	indices := reference.Named("PoolSelectionRef", "candidate_indices")
	if indices.Len() != p.count {
		return CBORFailure("pool_index_membership")
	}
	for i, member := range w.members[:p.count] {
		index, ok := indices.Index(i).Uint()
		if !ok || index != member.Index {
			return CBORFailure("pool_index_membership")
		}
	}
	for _, item := range []struct {
		value Value
		want  [32]byte
	}{
		{root.Named(c.schema, "artifact_digest"), p.artifactDigest},
		{reference.Named("PoolSelectionRef", "artifact_digest"), p.artifactDigest},
		{reference.Named("PoolSelectionRef", "candidate_set_digest"), p.candidateSetDigest},
		{root.Named(c.schema, "route_selection"), p.routeSetDigest},
	} {
		value, ok := item.value.ByteString()
		if !ok || !bytes.Equal(value, item.want[:]) {
			return CBORFailure("pool_digest_binding")
		}
	}
	once := reference.Named("PoolSelectionRef", "once_authority_ref")
	for _, names := range [][2]string{{"tenant_id", "tenant_id"}, {"artifact_issuer_key_id", "artifact_issuer_key_id"}, {"spend_authority_id", "authority_id"}} {
		left, right := once.Named("OnceAuthorityRef", names[0]).Encoded(), root.Named(c.schema, names[1]).Encoded()
		if len(left) == 0 || !bytes.Equal(left, right) {
			return CBORFailure("pool_authority_binding")
		}
	}
	return nil
}

func (p *PoolSelection) Member(index uint64, id [16]byte, route [32]byte) bool {
	w := p.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != p {
		return false
	}
	for _, member := range w.members[:p.count] {
		if member.Index == index && member.CandidateID == id && member.RouteDigest == route {
			return true
		}
	}
	return false
}

// MemberAt returns detached selection metadata in the original signed order.
func (p *PoolSelection) MemberAt(position int) (PoolMember, error) {
	if p == nil || p.workspace == nil {
		return PoolMember{}, CBORFailure("pool_owner")
	}
	w := p.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != p || position < 0 || position >= p.count {
		return PoolMember{}, CBORFailure("pool_index_membership")
	}
	return w.members[position], nil
}

func (p *PoolSelection) Bytes() ([]byte, error) {
	w := p.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != p {
		return nil, CBORFailure("pool_owner")
	}
	return w.encoded[:p.size:p.size], nil
}

// Digests returns detached facts. Changing a caller's copy cannot alter proof
// matching. No proof, grant or activation right is carried by these hashes.
func (p *PoolSelection) Digests() (artifact, candidates, routes [32]byte, err error) {
	w := p.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != p {
		return artifact, candidates, routes, CBORFailure("pool_owner")
	}
	return p.artifactDigest, p.candidateSetDigest, p.routeSetDigest, nil
}

func (p *PoolSelection) Release() {
	w := p.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current == p {
		w.clear()
		w.current = nil
	}
}
