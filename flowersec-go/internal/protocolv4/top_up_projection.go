package protocolv4

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
)

type topUpProjection struct {
	schema  string
	count   int
	omitted [2]uint64
}

var topUpRawProjections = sync.OnceValues(func() (map[string]topUpProjection, error) {
	var domains []struct {
		Name, Operation string
		Label           string `json:"label_bytes"`
		Input           struct {
			Parts []struct {
				Schema     string `json:"schema_ref"`
				Projection string
				Fields     []string
			}
		} `json:"input_schema"`
	}
	if json.Unmarshal([]byte(DomainRegistryJSON), &domains) != nil {
		return nil, CBORFailure("registry_unresolved")
	}
	registry, err := runtimeSchema()
	if err != nil {
		return nil, err
	}
	result := make(map[string]topUpProjection, 2)
	for _, d := range domains {
		if d.Name != "topup_request_digest" && d.Name != "topup_response_digest" {
			continue
		}
		if d.Operation != "sha256-raw" || d.Label != "" || len(d.Input.Parts) != 1 {
			return nil, CBORFailure("registry_unresolved")
		}
		part := d.Input.Parts[0]
		m := registry.Maps[part.Schema]
		if m == nil || part.Projection != "without_fields_raw" || len(part.Fields) < 1 || len(part.Fields) > 2 {
			return nil, CBORFailure("registry_unresolved")
		}
		p := topUpProjection{schema: part.Schema, count: len(part.Fields)}
		for i, name := range part.Fields {
			f := m.byName[name]
			if f == nil {
				return nil, CBORFailure("registry_unresolved")
			}
			p.omitted[i] = f.id
		}
		result[d.Name] = p
	}
	if len(result) != 2 {
		return nil, CBORFailure("registry_unresolved")
	}
	return result, nil
})

// rawTopUpDigest preserves original canonical field bytes using only the
// generated raw-map projection. No domain label or length prefix is added.
func rawTopUpDigest(doc *Document, dst []byte, name string) ([32]byte, error) {
	projection, err := topUpRawProjections()
	if err != nil {
		return [32]byte{}, err
	}
	p, ok := projection[name]
	if !ok || doc == nil || !doc.Root().valid() || doc.schema != p.schema {
		return [32]byte{}, CBORFailure("projection_field")
	}
	d := doc.decoder
	root := d.nodes[doc.root]
	if root.major != 5 || root.n < uint64(p.count) {
		return [32]byte{}, CBORFailure("projection_field")
	}
	for _, id := range p.omitted[:p.count] {
		if d.lookup(doc.root, id) < 0 {
			return [32]byte{}, CBORFailure("projection_field")
		}
	}
	n, err := cborHead(dst, 5, root.n-uint64(p.count))
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(dst)
	for key := root.first; key >= 0; {
		value := d.nodes[key].next
		omit := false
		for _, id := range p.omitted[:p.count] {
			omit = omit || d.nodes[key].n == id
		}
		if !omit {
			part := d.input[d.nodes[key].start:d.nodes[value].end]
			if len(part) > len(dst)-n {
				return [32]byte{}, CBORFailure("encoder_capacity")
			}
			n += copy(dst[n:], part)
		}
		key = d.nodes[value].next
	}
	return sha256.Sum256(dst[:n]), nil
}

// TopUpIdentityDigest binds stored bytes to the original certificate digest.
// The caller must already have verified this complete canonical certificate;
// this hash alone provides no signature, trust or key-possession evidence.
func TopUpIdentityDigest(certificate []byte) ([32]byte, error) {
	limit, err := SchemaByteLimit("IdentityCertificate")
	if err != nil {
		return [32]byte{}, err
	}
	if len(certificate) == 0 || len(certificate) > limit {
		return [32]byte{}, CBORFailure("configuration_capacity")
	}
	return fullMapDigest("certificate_digest", "IdentityCertificate", certificate)
}
