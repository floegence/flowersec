package protocolv4

// Test-only external digest/member oracles over the independent Go receiver.
// These projections grant no trust, admission, claim, dispatch or winner rights.
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strconv"
	"testing"
)

func (r *cborReference) namedField(name, fieldName string) (uint64, *cborRefField, error) {
	for id, field := range r.registry.Maps[name].Fields {
		if field.Name == fieldName {
			n, err := strconv.ParseUint(id, 10, 16)
			if err != nil {
				return 0, nil, cborRefError("registry_unresolved")
			}
			return n, field, nil
		}
	}
	return 0, nil, cborRefError("unknown_field")
}

func (r *cborReference) namedValue(name string, value *cborRefValue, field string) (*cborRefValue, error) {
	id, _, err := r.namedField(name, field)
	if err != nil {
		return nil, err
	}
	return cborLookup(value, id), nil
}

// Ordering field IDs is issuer construction, not repair of received bytes or
// of the caller's index sequence. Values keep their original representation.
func (r *cborReference) namedMap(name string, fields map[string]*cborRefValue) (*cborRefValue, error) {
	value := &cborRefValue{major: 5}
	for key, item := range fields {
		id, _, err := r.namedField(name, key)
		if err != nil {
			return nil, err
		}
		if item != nil {
			value.pairs = append(value.pairs, [2]*cborRefValue{{major: 0, n: id}, item})
		}
	}
	sort.Slice(value.pairs, func(i, j int) bool { return value.pairs[i][0].n < value.pairs[j][0].n })
	return value, nil
}

func cborSingleMapHash(domainName, schemaName, projection string, encoded []byte) ([]byte, error) {
	var domains []struct {
		Name, Operation string
		Label           string `json:"label_bytes"`
		OutputLength    uint64 `json:"output_length"`
		InputSchema     struct {
			Parts []struct {
				Encoding, Projection string
				SchemaRef            string `json:"schema_ref"`
			}
		} `json:"input_schema"`
	}
	if json.Unmarshal([]byte(DomainRegistryJSON), &domains) != nil {
		return nil, cborRefError("registry_unresolved")
	}
	for _, domain := range domains {
		if domain.Name != domainName {
			continue
		}
		if domain.Operation != "sha256" || domain.OutputLength != sha256.Size || len(domain.InputSchema.Parts) != 1 {
			return nil, cborRefError("domain_projection")
		}
		part := domain.InputSchema.Parts[0]
		if part.Encoding != "lp-map" || part.Projection != projection || part.SchemaRef != schemaName {
			return nil, cborRefError("domain_projection")
		}
		label, err := hex.DecodeString(domain.Label)
		if err != nil {
			return nil, cborRefError("registry_unresolved")
		}
		if uint64(len(encoded)) > uint64(^uint32(0)) {
			return nil, cborRefError("map_size")
		}
		h := sha256.New()
		_, _ = h.Write(label)
		_, _ = h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(encoded))))
		_, _ = h.Write(encoded)
		return h.Sum(nil), nil
	}
	return nil, cborRefError("registry_unresolved")
}

func (r *cborReference) openDigest(value *cborRefValue) ([]byte, error) {
	id, _, err := r.namedField("OPEN_STREAM", "open_digest")
	if err != nil {
		return nil, err
	}
	if value == nil || value.major != 5 || cborLookup(value, id) == nil {
		return nil, cborRefError("missing_field")
	}
	unsigned := &cborRefValue{major: 5}
	for _, pair := range value.pairs {
		if pair[0].n != id {
			unsigned.pairs = append(unsigned.pairs, pair)
		}
	}
	return cborSingleMapHash("open_digest", "OPEN_STREAM", "without_open_digest", unsigned.encode(nil))
}

func (r *cborTextReference) projectCandidate(candidate *cborRefValue) (*cborRefValue, error) {
	projection, ok := r.registry.MapProjections["candidate_route"]
	if !ok {
		return nil, cborRefError("projection_unresolved")
	}
	encoded := candidate.encode(nil)
	if _, err := r.wireMap(encoded, projection.Source, cborShapeContext{}, uint64(len(encoded))+1); err != nil {
		return nil, err
	}
	fields := map[string]*cborRefValue{}
	for _, field := range projection.Fields {
		value, err := r.namedValue(projection.Source, candidate, field)
		if err != nil {
			return nil, err
		}
		fields[field] = value
	}
	result, err := r.namedMap(projection.Target, fields)
	if err != nil {
		return nil, err
	}
	encoded = result.encode(nil)
	return r.wireMap(encoded, projection.Target, cborShapeContext{}, uint64(len(encoded))+1)
}

type cborPoolMember struct {
	index                    uint64
	candidateID, routeDigest []byte
}

type cborPoolProjection struct {
	encoded, artifactDigest, candidateSetDigest, routeSetDigest []byte
	members                                                     []cborPoolMember
}

func (r *cborTextReference) derivePool(artifactBytes []byte, indices []uint64, ownerCap uint64) (*cborPoolProjection, error) {
	artifact, err := r.wireMap(artifactBytes, "Artifact", cborShapeContext{}, ownerCap)
	if err != nil {
		return nil, err
	}
	_, indexField, err := r.namedField("PoolSelectionRef", "candidate_indices")
	if err != nil {
		return nil, err
	}
	// Check the complete list bound before allocating per-index state.
	if indexField.MinItems == nil || indexField.MaxItems == nil {
		return nil, cborRefError("registry_unresolved")
	}
	if uint64(len(indices)) < uint64(*indexField.MinItems) || uint64(len(indices)) > uint64(*indexField.MaxItems) {
		return nil, cborRefError("array_length")
	}
	candidates, err := r.namedValue("Artifact", artifact, "candidates")
	if err != nil || candidates == nil || candidates.major != 4 {
		return nil, cborRefError("field_type")
	}
	result := &cborPoolProjection{}
	entries := &cborRefValue{major: 4}
	for _, index := range indices {
		n := &cborRefValue{major: 0, n: index}
		if err := r.shapeField(indexField.Items, n, cborShapeContext{}); err != nil {
			return nil, err
		}
		if index >= uint64(len(candidates.items)) {
			return nil, cborRefError("pool_index_membership")
		}
		candidate := candidates.items[int(index)]
		route, err := r.projectCandidate(candidate)
		if err != nil {
			return nil, err
		}
		routeDigest, err := cborSingleMapHash("route_digest", "Route", "full", route.encode(nil))
		if err != nil {
			return nil, err
		}
		id, err := r.namedValue("Candidate", candidate, "candidate_id")
		if err != nil || id == nil || id.major != 2 {
			return nil, cborRefError("field_type")
		}
		// Detach public IDs from the complete secret-bearing Artifact backing.
		member := cborPoolMember{index: index, candidateID: bytes.Clone(id.data), routeDigest: routeDigest}
		entry, err := r.namedMap("PoolRouteRef", map[string]*cborRefValue{
			"candidate_index": n, "candidate_id": {major: 2, data: member.candidateID}, "route_digest": {major: 2, data: member.routeDigest},
		})
		if err != nil {
			return nil, err
		}
		result.members = append(result.members, member)
		entries.items = append(entries.items, entry)
	}
	result.artifactDigest, err = cborSingleMapHash("artifact_digest", "Artifact", "full", artifactBytes)
	if err != nil {
		return nil, err
	}
	selection, err := r.namedMap("PoolSelectionSet", map[string]*cborRefValue{
		"artifact_digest": {major: 2, data: result.artifactDigest}, "entries": entries,
	})
	if err != nil {
		return nil, err
	}
	result.encoded = selection.encode(nil)
	// This rejects duplicate or decreasing original indices. Never sort them.
	if _, err := r.wireMap(result.encoded, "PoolSelectionSet", cborShapeContext{}, uint64(len(result.encoded))+1); err != nil {
		return nil, err
	}
	result.candidateSetDigest, err = cborSingleMapHash("candidate_set_digest", "PoolSelectionSet", "full", result.encoded)
	if err != nil {
		return nil, err
	}
	result.routeSetDigest, err = cborSingleMapHash("route_set_digest", "PoolSelectionSet", "full", result.encoded)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *cborTextReference) verifyPoolSet(artifact []byte, indices []uint64, received []byte, ownerCap uint64) (*cborPoolProjection, error) {
	if _, err := r.wireMap(received, "PoolSelectionSet", cborShapeContext{}, ownerCap); err != nil {
		return nil, err
	}
	result, err := r.derivePool(artifact, indices, ownerCap)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(result.encoded, received) {
		return nil, cborRefError("pool_set_membership")
	}
	return result, nil
}

// v4.cbor.external_oracles
func TestCBORExternalOracleCorpus(t *testing.T) {
	r := newCBORTextReference(t)
	positive, negative, pools, opens := 0, 0, 0, 0
	for _, vector := range cborRefVectors(t) {
		t.Run(vector.ID, func(t *testing.T) {
			input, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input)
			value, err := r.wireMap(input, vector.Schema, shapeContext(vector.Limits), uint64(len(input))+1)
			if err == nil && vector.PoolDerivation != nil {
				if vector.Schema != "PoolSelectionSet" {
					t.Fatal("pool fixture schema drift")
				}
				pools++
				artifact, decodeErr := hex.DecodeString(vector.PoolDerivation.ArtifactHex)
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				_, err = r.verifyPoolSet(artifact, vector.PoolDerivation.Indices, input, uint64(max(len(artifact), len(input)))+1)
			}
			if err == nil && vector.Schema == "OPEN_STREAM" {
				opens++
				var digest []byte
				digest, err = r.openDigest(value)
				if err == nil {
					supplied, lookupErr := r.namedValue(vector.Schema, value, "open_digest")
					if lookupErr != nil {
						t.Fatal(lookupErr)
					}
					if !bytes.Equal(supplied.data, digest) {
						err = cborRefError("open_digest_mismatch")
					}
				}
			}
			if !bytes.Equal(input, original) {
				t.Fatal("receiver changed wire bytes")
			}
			if vector.ExpectedError != "" {
				negative++
				if err == nil {
					t.Fatalf("accepted invalid fixture: %s", vector.ExpectedError)
				}
				if vector.ExpectedError == "open_digest_mismatch" || vector.ExpectedError == "pool_set_membership" {
					if err.Error() != vector.ExpectedError {
						t.Fatalf("external oracle bypassed: %v", err)
					}
				}
				return
			}
			positive++
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(value.encode(nil), input) {
				t.Fatal("canonical re-encoding differs")
			}
		})
	}
	if positive == 0 || negative == 0 || pools == 0 || opens == 0 {
		t.Fatal("missing oracle coverage")
	}
	t.Logf("%d positive / %d negative corpus cases, %d pool and %d OPEN recomputations", positive, negative, pools, opens)
}

func oracleSeed(t testing.TB, id string) cborRefVector {
	t.Helper()
	for _, vector := range cborRefVectors(t) {
		if vector.ID == id {
			return vector
		}
	}
	t.Fatalf("missing oracle seed %s", id)
	return cborRefVector{}
}

func oracleBytes(t testing.TB, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func oracleField(t testing.TB, r *cborReference, name string, value *cborRefValue, field string) *cborRefValue {
	t.Helper()
	item, err := r.namedValue(name, value, field)
	if err != nil || item == nil {
		t.Fatalf("missing oracle field %s.%s: %v", name, field, err)
	}
	return item
}

// v4.cbor.open_digest_binding
func TestCBOROpenDigestBinding(t *testing.T) {
	r := newCBORTextReference(t)
	seed := oracleSeed(t, "open_fields")
	input := oracleBytes(t, seed.Hex)
	value, err := r.wireMap(input, seed.Schema, shapeContext(seed.Limits), uint64(len(input)))
	if err != nil {
		t.Fatal(err)
	}
	want, err := r.openDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	// Isolate digest coverage: individual field mutations need not be valid
	// OPEN requests. Structural rejection still precedes this digest oracle.
	for _, field := range r.registry.Maps[seed.Schema].Fields {
		t.Run(field.Name, func(t *testing.T) {
			value, err := r.wireMap(input, seed.Schema, shapeContext(seed.Limits), uint64(len(input)))
			if err != nil {
				t.Fatal(err)
			}
			item := oracleField(t, r.cborReference, seed.Schema, value, field.Name)
			switch item.major {
			case 0:
				item.n ^= 1
			case 2, 3:
				item.data = append(bytes.Clone(item.data), 'x')
			default:
				t.Fatal("uncovered OPEN field type")
			}
			got, err := r.openDigest(value)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, want) != (field.Name == "open_digest") {
				t.Fatal("wrong digest projection")
			}
		})
	}
	if !bytes.Equal(input, oracleBytes(t, seed.Hex)) {
		t.Fatal("digest projection mutated input")
	}
	if _, err := cborSingleMapHash("open_digest", "OPEN_STREAM", "full", input); err != cborRefError("domain_projection") {
		t.Fatal("full-map OPEN domain accepted")
	}
	if _, err := cborSingleMapHash("route_digest", "Artifact", "full", input); err != cborRefError("domain_projection") {
		t.Fatal("cross-schema digest accepted")
	}
}

// v4.cbor.pool_domains
func TestCBORPoolDomains(t *testing.T) {
	r := newCBORTextReference(t)
	raw, err := os.ReadFile("../../../testdata/transport_v4/domains.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaSHA256 string `json:"schema_sha256"`
		Vectors      []struct {
			Domain string
			Inputs map[string]json.RawMessage
			Result struct {
				OutputHex string `json:"output_hex"`
			}
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaSHA256 != SchemaSHA256 {
		t.Fatal("domain schema drift")
	}
	checks := 0
	for _, id := range []string{"pool_set_one", "pool_set_two", "pool_set_sixteen"} {
		seed := oracleSeed(t, id)
		artifact := oracleBytes(t, seed.PoolDerivation.ArtifactHex)
		result, err := r.derivePool(artifact, seed.PoolDerivation.Indices, uint64(len(artifact)))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(result.candidateSetDigest, result.routeSetDigest) {
			t.Fatal("pool domains conflated")
		}
		for name, digest := range map[string][]byte{"candidate_set_digest": result.candidateSetDigest, "route_set_digest": result.routeSetDigest} {
			found := false
			for _, vector := range corpus.Vectors {
				if vector.Domain != name {
					continue
				}
				var selection struct {
					Bytes string `json:"$bytes"`
				}
				if err := json.Unmarshal(vector.Inputs["selection"], &selection); err != nil {
					t.Fatal(err)
				}
				if selection.Bytes == hex.EncodeToString(result.encoded) {
					if !bytes.Equal(digest, oracleBytes(t, vector.Result.OutputHex)) {
						t.Fatal("independent pool digest differs")
					}
					found = true
					checks++
				}
			}
			if !found {
				t.Fatalf("missing %s domain fixture for %s", name, id)
			}
		}
	}
	if checks != 6 {
		t.Fatalf("expected six independent domain comparisons, got %d", checks)
	}
}

// v4.cbor.pool_boundaries
func TestCBORPoolBoundaries(t *testing.T) {
	r := newCBORTextReference(t)
	seed := oracleSeed(t, "pool_set_two")
	artifact := oracleBytes(t, seed.PoolDerivation.ArtifactHex)
	indices := seed.PoolDerivation.Indices
	result, err := r.derivePool(artifact, indices, uint64(len(artifact)))
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range [][]uint64{nil, {0, 0}, {1, 0}, {2}, {16}, {^uint64(0)}, make([]uint64, 17)} {
		original := append([]uint64(nil), selection...)
		if got, err := r.derivePool(artifact, selection, uint64(len(artifact))); err == nil || got != nil {
			t.Fatalf("accepted invalid indices %v", selection)
		}
		if !reflect.DeepEqual(selection, original) {
			t.Fatal("repaired caller indices")
		}
	}
	if got, err := r.derivePool(artifact, indices, uint64(len(artifact)-1)); err != cborRefError("map_size") || got != nil {
		t.Fatal("Artifact owner cap bypassed")
	}
	for _, index := range indices {
		subset := []uint64{index}
		if _, err := r.derivePool(artifact, subset, uint64(len(artifact))); err != nil {
			t.Fatal("valid strict subset rejected", err)
		}
		if got, err := r.verifyPoolSet(artifact, subset, result.encoded, uint64(len(artifact))); err != cborRefError("pool_set_membership") || got != nil {
			t.Fatal("received set was repaired to subset")
		}
	}
	for _, field := range []string{"artifact_digest", "candidate_id", "route_digest"} {
		t.Run(field, func(t *testing.T) {
			selection, err := r.wireMap(result.encoded, "PoolSelectionSet", cborShapeContext{}, uint64(len(result.encoded)))
			if err != nil {
				t.Fatal(err)
			}
			name, root := "PoolSelectionSet", selection
			if field != "artifact_digest" {
				name = "PoolRouteRef"
				root = oracleField(t, r.cborReference, "PoolSelectionSet", selection, "entries").items[0]
			}
			item := oracleField(t, r.cborReference, name, root, field)
			item.data = bytes.Clone(item.data)
			item.data[0] ^= 0x80
			changed := selection.encode(nil)
			if _, err := r.wireMap(changed, "PoolSelectionSet", cborShapeContext{}, uint64(len(changed))); err != nil {
				t.Fatal("member mutation changed shape", err)
			}
			if got, err := r.verifyPoolSet(artifact, indices, changed, uint64(len(artifact))); err != cborRefError("pool_set_membership") || got != nil {
				t.Fatal("forged member accepted")
			}
		})
	}
	for _, field := range []string{"signature", "priority", "port"} {
		t.Run("artifact_"+field, func(t *testing.T) {
			value, err := r.wireMap(artifact, "Artifact", cborShapeContext{}, uint64(len(artifact)))
			if err != nil {
				t.Fatal(err)
			}
			name, root := "Artifact", value
			if field != "signature" {
				name = "Candidate"
				root = oracleField(t, r.cborReference, "Artifact", value, "candidates").items[0]
				if field == "priority" {
					candidates := oracleField(t, r.cborReference, "Artifact", value, "candidates").items
					root = candidates[len(candidates)-1]
				}
				if field == "port" {
					root = oracleField(t, r.cborReference, name, root, "direct_leg")
					name = "Leg"
				}
			}
			item := oracleField(t, r.cborReference, name, root, field)
			if item.major == 2 {
				item.data = bytes.Clone(item.data)
				item.data[0] ^= 1
			} else {
				item.n++
			}
			changed := value.encode(nil)
			derived, err := r.derivePool(changed, indices, uint64(len(changed)))
			if err != nil {
				t.Fatal("Artifact mutation changed field/rule validity", err)
			}
			if bytes.Equal(derived.artifactDigest, result.artifactDigest) {
				t.Fatal("full Artifact binding omitted field")
			}
			routeChanged := !bytes.Equal(derived.members[0].routeDigest, result.members[0].routeDigest)
			if routeChanged != (field == "port") {
				t.Fatal("route projection included or omitted the wrong field")
			}
			if got, err := r.verifyPoolSet(changed, indices, result.encoded, uint64(max(len(changed), len(result.encoded)))); err != cborRefError("pool_set_membership") || got != nil {
				t.Fatal("original set accepted for changed signed Artifact")
			}
		})
	}
	if !bytes.Equal(artifact, oracleBytes(t, seed.PoolDerivation.ArtifactHex)) {
		t.Fatal("mutated secret-bearing source")
	}
	// Retained public values must not alias the input's secret-bearing backing.
	snapshot := cborPoolProjection{
		encoded: bytes.Clone(result.encoded), artifactDigest: bytes.Clone(result.artifactDigest),
		candidateSetDigest: bytes.Clone(result.candidateSetDigest), routeSetDigest: bytes.Clone(result.routeSetDigest),
		members: make([]cborPoolMember, len(result.members)),
	}
	for i, member := range result.members {
		snapshot.members[i] = cborPoolMember{index: member.index, candidateID: bytes.Clone(member.candidateID), routeDigest: bytes.Clone(member.routeDigest)}
	}
	clear(artifact)
	if !reflect.DeepEqual(snapshot, *result) {
		t.Fatal("public projection aliases Artifact input")
	}
}

// v4.cbor.pool_fuzz
func FuzzCBORPoolReference(f *testing.F) {
	r := newCBORTextReference(f)
	for _, id := range []string{"pool_set_one", "pool_set_two", "pool_set_sixteen"} {
		seed := oracleSeed(f, id)
		indices := make([]byte, len(seed.PoolDerivation.Indices))
		for i, index := range seed.PoolDerivation.Indices {
			indices[i] = byte(index)
		}
		f.Add(oracleBytes(f, seed.PoolDerivation.ArtifactHex), indices)
	}
	f.Fuzz(func(t *testing.T, artifact, indexBytes []byte) {
		if len(artifact) > 1<<16 || len(indexBytes) > 17 {
			return
		}
		original := bytes.Clone(artifact)
		indices := make([]uint64, len(indexBytes))
		for i, index := range indexBytes {
			indices[i] = uint64(index)
		}
		result, err := r.derivePool(artifact, indices, 1<<16)
		if !bytes.Equal(artifact, original) {
			t.Fatal("pool derivation changed Artifact input")
		}
		if err != nil {
			if result != nil {
				t.Fatal("partial failed pool result")
			}
			return
		}
		verified, err := r.verifyPoolSet(artifact, indices, result.encoded, 1<<16)
		if err != nil || !bytes.Equal(result.encoded, verified.encoded) {
			t.Fatal("pool round-trip failed", err)
		}
		if len(result.members) != len(indices) {
			t.Fatal("pool lost members")
		}
		for i, member := range result.members {
			if member.index != indices[i] || i > 0 && indices[i-1] >= member.index {
				t.Fatal("pool index order drift")
			}
		}
	})
}
