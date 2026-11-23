package protocolv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
)

type frameRule struct {
	Op, Field, Discriminator, Left, Right string
	Min, Max                              *wireBound
	Value                                 json.RawMessage
	Absent, Required, Nonzero             []string
	Constants                             map[string]json.RawMessage
	Equal                                 [][2]string
	LessOrEqual                           [][2]string `json:"less_or_equal"`
	ItemFieldID                           *uint64     `json:"item_field_id"`
	CodeField                             string      `json:"code_field"`
	TargetScopeField                      string      `json:"target_scope_field"`
	StreamIDField                         string      `json:"stream_id_field"`
	RetryAfterField                       string      `json:"retry_after_field"`
}
type frameRuntime struct {
	rules  map[string][]frameRule
	errors map[uint64]struct {
		Scope     string
		Retryable bool
	}
	openLabel []byte
}

var runtimeFrames = sync.OnceValues(func() (*frameRuntime, error) {
	r := &frameRuntime{rules: map[string][]frameRule{}, errors: map[uint64]struct {
		Scope     string
		Retryable bool
	}{}}
	var source struct{ Variants, Relations map[string][]json.RawMessage }
	var syntax struct {
		Variants  map[string][]json.RawMessage `json:"variant_rules"`
		Relations map[string][]json.RawMessage `json:"relation_rules"`
	}
	if json.Unmarshal([]byte(CBORSyntaxRegistryJSON), &syntax) != nil {
		return nil, CBORFailure("registry_unresolved")
	}
	source.Variants, source.Relations = syntax.Variants, syntax.Relations
	for _, family := range []map[string][]json.RawMessage{source.Variants, source.Relations} {
		for name, rules := range family {
			if !recordSchema(name) {
				continue
			}
			for _, raw := range rules {
				var rule frameRule
				decoder := json.NewDecoder(bytes.NewReader(raw))
				decoder.DisallowUnknownFields()
				if decoder.Decode(&rule) != nil {
					return nil, CBORFailure("rule_unresolved")
				}
				r.rules[name] = append(r.rules[name], rule)
			}
		}
	}
	registry, err := runtimeSchema()
	if err != nil {
		return nil, err
	}
	var codes map[string]uint64
	var metadata map[string]struct {
		Scope     string
		Retryable bool
	}
	if json.Unmarshal(registry.Fields["error_codes"], &codes) != nil || json.Unmarshal(registry.Fields["error_code_metadata"], &metadata) != nil {
		return nil, CBORFailure("registry_unresolved")
	}
	for name, code := range codes {
		entry, ok := metadata[name]
		if !ok {
			return nil, CBORFailure("registry_unresolved")
		}
		r.errors[code] = entry
	}
	var domains []struct {
		Name, Operation string
		Label           string `json:"label_bytes"`
	}
	if json.Unmarshal([]byte(DomainRegistryJSON), &domains) != nil {
		return nil, CBORFailure("registry_unresolved")
	}
	for _, domain := range domains {
		if domain.Name == "open_digest" {
			r.openLabel, err = hex.DecodeString(domain.Label)
			if err != nil || domain.Operation != "sha256" {
				return nil, CBORFailure("registry_unresolved")
			}
		}
	}
	if len(r.openLabel) == 0 {
		return nil, CBORFailure("registry_unresolved")
	}
	return r, nil
})

func recordSchema(name string) bool {
	switch name {
	case "OPEN_STREAM", "STREAM_DATA", "DATAGRAM", "ERROR", "CLOSE", "GOAWAY", "PING", "PONG", "OPEN_ACCEPT", "terminal_tuple", "RekeyBarrierEntry":
		return true
	}
	return strings.HasPrefix(name, "REKEY_") || strings.HasPrefix(name, "STREAM_ACK_")
}

// Frame holds the authenticated record's exact map. It grants no Stream, credit
// or rekey authority; the Session applies it under its original lifecycle gate.
type Frame struct {
	Document *Document
	Type     FrameType
	Header   RecordHeader
	Schema   string
}

func (f *Frame) Release()                { f.Document.Release() }
func (f *Frame) Field(name string) Value { return f.Document.Root().Named(f.Schema, name) }

// CopyMACProjection preserves the exact authenticated canonical field bytes.
// Only the registered MAC pair and the map count are removed.
func (f *Frame) CopyMACProjection(dst []byte) ([]byte, error) {
	d := f.Document.decoder
	m := d.registry.Maps[f.Schema]
	if m == nil || m.MACField == nil {
		return nil, CBORFailure("projection_unresolved")
	}
	return f.Document.copyWithout(dst, *m.MACField)
}

func (doc *Document) copyWithout(dst []byte, omitted uint64) ([]byte, error) {
	if !doc.Root().valid() {
		return nil, CBORFailure("document_released")
	}
	d := doc.decoder
	root := d.nodes[doc.root]
	if root.major != 5 || root.n == 0 || d.lookup(doc.root, omitted) < 0 {
		return nil, CBORFailure("projection_field")
	}
	offset, err := cborHead(dst, 5, root.n-1)
	if err != nil {
		return nil, err
	}
	for key := root.first; key >= 0; {
		value := d.nodes[key].next
		if d.nodes[key].n != omitted {
			part := d.input[d.nodes[key].start:d.nodes[value].end]
			if len(part) > len(dst)-offset {
				return nil, CBORFailure("encoder_capacity")
			}
			offset += copy(dst[offset:], part)
		}
		key = d.nodes[value].next
	}
	return dst[:offset:offset], nil
}

func (d *Decoder) DecodeRecordBody(input []byte, frame FrameType, header RecordHeader, direction Direction, context DecodeContext) (_ *Frame, err error) {
	if direction > ServerToClient {
		return nil, CBORFailure("direction")
	}
	if err := ValidateRecordScope(frame, header.Scope); err != nil {
		return nil, err
	}
	// Closed variant selection happens only in this already bounded canonical
	// map. No discriminator causes a second parse or allocates another owner.
	doc, err := d.DecodeShape(input, "", context)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			doc.Release()
		}
	}()
	schema, err := d.recordSchema(doc, frame)
	if err != nil {
		return nil, err
	}
	if err = d.shape(doc.root, &wireField{Type: "map", SchemaRef: schema}, &wireContext{external: &context}); err != nil {
		return nil, err
	}
	doc.schema = schema
	if role := d.registry.Maps[schema].SenderRole; role != nil && *role != uint64(direction) {
		return nil, CBORFailure("sender_role")
	}
	result := &Frame{Document: doc, Type: frame, Header: header, Schema: schema}
	r, err := runtimeFrames()
	if err != nil {
		return nil, err
	}
	for _, rule := range r.rules[schema] {
		if err = result.checkRule(rule, r); err != nil {
			return nil, err
		}
	}
	// Only maps carrying record mirrors compare these fields. A maintenance
	// ACK's direction names the acknowledged direction, not its record sender.
	if frame == FrameOpenStream || frame == FrameStreamData || frame == FrameDatagram {
		for name, want := range map[string]uint64{"epoch": uint64(header.Epoch), "sequence": header.Sequence} {
			actual, ok := result.Field(name).Uint()
			if !ok || actual != want {
				return nil, CBORFailure("record_mirror")
			}
		}
		name := "scope"
		if frame == FrameStreamData {
			name = "stream_id"
		}
		scope, ok := result.Field(name).Uint()
		if !ok || scope != header.Scope {
			return nil, CBORFailure("record_mirror")
		}
		if frame != FrameDatagram {
			actual, ok := result.Field("direction").Uint()
			if !ok || actual != uint64(direction) {
				return nil, CBORFailure("record_mirror")
			}
		}
	}
	if frame == FrameOpenStream {
		if Direction((header.Scope+1)%2) != direction {
			return nil, CBORFailure("scope_role")
		}
		digest, err := result.OpenDigest()
		if err != nil {
			return nil, err
		}
		actual, _ := result.Field("open_digest").ByteString()
		if !bytes.Equal(actual, digest[:]) {
			return nil, CBORFailure("open_digest")
		}
	}
	return result, nil
}

func (d *Decoder) recordSchema(doc *Document, frame FrameType) (string, error) {
	var fixed string
	switch frame {
	case FrameOpenStream:
		fixed = "OPEN_STREAM"
	case FrameStreamData:
		fixed = "STREAM_DATA"
	case FrameDatagram:
		fixed = "DATAGRAM"
	case FrameError:
		fixed = "ERROR"
	case FrameClose:
		fixed = "CLOSE"
	case FrameGoAway:
		fixed = "GOAWAY"
	case FramePing:
		fixed = "PING"
	case FramePong:
		fixed = "PONG"
	case FrameRekey, FrameStreamAck:
		// OPEN_ACCEPT has its registered discriminator after the common open
		// outcome fields. Its presence selects that closed schema exclusively.
		if frame == FrameStreamAck {
			field := d.registry.Maps["OPEN_ACCEPT"].byName["variant"]
			if v := doc.Root().Field(field.id); v.valid() {
				if n, ok := v.Uint(); ok && n == field.constant.n {
					return "OPEN_ACCEPT", nil
				}
				return "", CBORFailure("frame_variant")
			}
		}
		prefix, discriminator := "REKEY_", "phase"
		if frame == FrameStreamAck {
			prefix, discriminator = "STREAM_ACK_", "variant"
		}
		for name, m := range d.registry.Maps {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			field := m.byName[discriminator]
			if field == nil || field.constant == nil {
				continue
			}
			if n, ok := doc.Root().Field(field.id).Uint(); ok && n == field.constant.n {
				return name, nil
			}
		}
		return "", CBORFailure("frame_variant")
	default:
		return "", ErrUnknownFrame
	}
	return fixed, nil
}

func (f *Frame) path(path string) Value {
	v, m := f.Document.Root(), f.Document.decoder.registry.Maps[f.Schema]
	for path != "" {
		part, rest, _ := strings.Cut(path, ".")
		if m == nil {
			return Value{}
		}
		field := m.byName[part]
		if field == nil {
			return Value{}
		}
		v = v.Field(field.id)
		if !v.valid() {
			return Value{}
		}
		path = rest
		m = f.Document.decoder.registry.Maps[field.SchemaRef]
	}
	return v
}
func rawMatches(v Value, raw json.RawMessage) bool {
	if !v.valid() || len(raw) == 0 {
		return false
	}
	if raw[0] == 't' || raw[0] == 'f' {
		actual, ok := v.Bool()
		return ok && actual == (raw[0] == 't')
	}
	var n wireBound
	if json.Unmarshal(raw, &n) != nil {
		return false
	}
	actual, ok := v.Uint()
	return ok && actual == uint64(n)
}
func (f *Frame) checkRule(rule frameRule, r *frameRuntime) error {
	get := f.path
	switch rule.Op {
	case "range":
		v, ok := get(rule.Field).Uint()
		if !ok || rule.Min == nil || rule.Max == nil || v < uint64(*rule.Min) || v > uint64(*rule.Max) {
			return CBORFailure("field_range")
		}
	case "equal":
		a, b := get(rule.Left), get(rule.Right)
		if !a.valid() || !b.valid() || !bytes.Equal(a.Encoded(), b.Encoded()) {
			return CBORFailure("field_equality")
		}
	case "less_or_equal":
		a, ok := get(rule.Left).Uint()
		b, yes := get(rule.Right).Uint()
		if !ok || !yes || a > b {
			return CBORFailure("field_order")
		}
	case "variant":
		if !rawMatches(get(rule.Discriminator), rule.Value) {
			return nil
		}
		for _, name := range rule.Absent {
			if get(name).valid() {
				return CBORFailure("variant_absent")
			}
		}
		for _, name := range rule.Required {
			if !get(name).valid() {
				return CBORFailure("variant_required")
			}
		}
		for name, want := range rule.Constants {
			if !rawMatches(get(name), want) {
				return CBORFailure("variant_constant")
			}
		}
		for _, names := range rule.Equal {
			if !bytes.Equal(get(names[0]).Encoded(), get(names[1]).Encoded()) {
				return CBORFailure("field_equality")
			}
		}
		for _, names := range rule.LessOrEqual {
			a, ok := get(names[0]).Uint()
			b, yes := get(names[1]).Uint()
			if !ok || !yes || a > b {
				return CBORFailure("field_order")
			}
		}
		for _, name := range rule.Nonzero {
			v, ok := get(name).Uint()
			if !ok || v == 0 {
				return CBORFailure("field_nonzero")
			}
		}
	case "increasing", "increasing_scopes":
		v := get(rule.Field)
		var previous uint64
		// Iterate the arena once; Index(i) would be quadratic for barriers.
		d := f.Document.decoder
		node := d.nodes[v.index]
		for index, child := 0, node.first; child >= 0; index, child = index+1, d.nodes[child].next {
			item := Value{f.Document, child}
			if rule.ItemFieldID != nil {
				item = item.Field(*rule.ItemFieldID)
			}
			n, ok := item.Uint()
			if !ok || index > 0 && n <= previous {
				return CBORFailure("item_order")
			}
			if rule.Op == "increasing_scopes" && (n == 0 || n >= DatagramScope()-1) {
				return CBORFailure("scope_order")
			}
			previous = n
		}
	case "error_scope":
		code, ok := get(rule.CodeField).Uint()
		if !ok {
			return CBORFailure("enum_value")
		}
		policy, ok := r.errors[code]
		if !ok {
			return CBORFailure("enum_value")
		}
		target, ok := get(rule.TargetScopeField).Uint()
		if !ok {
			return CBORFailure("error_scope")
		}
		stream := get(rule.StreamIDField)
		if policy.Scope == "session" && (target != 0 || stream.valid()) {
			return CBORFailure("error_scope")
		}
		if policy.Scope == "stream" {
			n, ok := stream.Uint()
			if !ok || target == 0 || n != target {
				return CBORFailure("error_scope")
			}
		}
		if !policy.Retryable && get(rule.RetryAfterField).valid() {
			return CBORFailure("retry_after_forbidden")
		}
	default:
		return CBORFailure("rule_unresolved")
	}
	return nil
}

// OpenDigest hashes the canonical map projection directly from its original
// snapshot. Only the registered digest field and map pair count are replaced.
func (f *Frame) OpenDigest() ([32]byte, error) {
	var result [32]byte
	if f.Schema != "OPEN_STREAM" {
		return result, CBORFailure("unknown_schema")
	}
	r, err := runtimeFrames()
	if err != nil {
		return result, err
	}
	d := f.Document.decoder
	root := d.nodes[f.Document.root]
	id := d.registry.Maps[f.Schema].byName["open_digest"].id
	var head [9]byte
	n, err := cborHead(head[:], 5, root.n-1)
	if err != nil {
		return result, err
	}
	size := n
	for key := root.first; key >= 0; {
		value := d.nodes[key].next
		if d.nodes[key].n != id {
			size += d.nodes[value].end - d.nodes[key].start
		}
		key = d.nodes[value].next
	}
	h := sha256.New()
	h.Write(r.openLabel)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(size))
	h.Write(length[:])
	h.Write(head[:n])
	for key := root.first; key >= 0; {
		value := d.nodes[key].next
		if d.nodes[key].n != id {
			h.Write(d.input[d.nodes[key].start:d.nodes[value].end])
		}
		key = d.nodes[value].next
	}
	h.Sum(result[:0])
	return result, nil
}
