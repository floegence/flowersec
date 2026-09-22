package protocolv4

import (
	"bytes"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/unicode151"
)

// This cursor is private to the fixed snapshot reader. It borrows immutable
// original response bytes; no input copy, recursive decode or general-purpose
// caller callback is hidden behind a step. Each step parses one atom, validates
// one field, or checks one bounded registry rule. Opaque byte strings are skipped
// by length, not scanned. Hashing and copying them are separate bounded phases.
type contractDecodeCursor struct {
	decoder    *Decoder
	schema     string
	context    DecodeContext
	rootField  wireField
	frames     [9]contractParseFrame
	depth, pos int
	// The closed graph has at most 358 field visits: 64 four-field error
	// definitions, the contract, and its optional stream content policy.
	plan                          [384]contractShapeEntry
	contexts                      [72]wireContext
	planned, shaped, contextCount int
	ruleAt, ruleGroup, ruleIndex  int
	phase                         uint8
	document                      *Document
}
type contractParseFrame struct {
	index, previous, previousKey int
	remaining, seen              uint64
	field                        *wireField
}
type contractShapeEntry struct {
	index   int
	field   *wireField
	context *wireContext
}

func borrowedContractDecoder(byteCap, nodeCap, textCap int) (*Decoder, error) {
	if _, err := decoderBackingBytes(byteCap, nodeCap, textCap); err != nil {
		return nil, err
	}
	registry, err := runtimeSchema()
	if err != nil {
		return nil, err
	}
	space, _ := unicode151.NormalizationSpace(textCap)
	return &Decoder{registry: registry, nodes: make([]cborNode, nodeCap), work: make([]rune, space), scratch: make([]rune, space), textCap: textCap, borrowed: true}, nil
}

func (c *contractDecodeCursor) begin(d *Decoder, wire []byte, schema string) error {
	if c.decoder != nil || d == nil || !d.borrowed || d.active || (schema != "ServiceContract" && schema != "ContractSnapshots") {
		return CBORFailure("decoder_busy")
	}
	if d.registry.Encoding.MaxDepth >= len(c.frames) {
		return CBORFailure("configuration_capacity")
	}
	m := d.registry.Maps[schema]
	if m == nil {
		return CBORFailure("unknown_schema")
	}
	if err := mapLength(m, uint64(len(wire)), &c.context); err != nil {
		return err
	}
	if d.generation == ^uint64(0) {
		return CBORFailure("decoder_retired")
	}
	d.generation++
	d.active, d.input, d.size, d.used = true, wire, len(wire), 0
	c.decoder, c.schema = d, schema
	c.rootField = wireField{Type: "map", SchemaRef: schema}
	c.contexts[0] = wireContext{external: &c.context}
	c.contextCount = 1
	c.document = &Document{decoder: d, generation: d.generation, schema: schema}
	return nil
}

func (c *contractDecodeCursor) parse() error {
	d := c.decoder
	// Complete exhausted containers without revisiting their contents.
	for c.depth > 0 && c.frames[c.depth-1].remaining == 0 {
		frame := &c.frames[c.depth-1]
		d.nodes[frame.index].end = c.pos
		*frame = contractParseFrame{}
		c.depth--
	}
	if c.depth == 0 && d.used != 0 {
		if c.pos != d.size {
			return CBORFailure("trailing_bytes")
		}
		c.plan[0] = contractShapeEntry{0, &c.rootField, &c.contexts[0]}
		c.planned, c.phase = 1, 1
		return nil
	}
	field := &c.rootField
	var parent *contractParseFrame
	if c.depth > 0 {
		parent = &c.frames[c.depth-1]
		node := d.nodes[parent.index]
		field = nil
		if node.major == 4 && parent.field != nil {
			field = parent.field.Items
		}
		if node.major == 5 && parent.seen%2 == 1 {
			key := d.nodes[parent.previous]
			if parent.field != nil {
				if m := d.registry.Maps[parent.field.SchemaRef]; m != nil {
					field = m.byID[key.n]
					if field == nil {
						return CBORFailure("unknown_field")
					}
				}
			}
		}
	}
	index, err := d.itemHead(&c.pos, d.size, c.depth, field, &c.context)
	if err != nil {
		return err
	}
	node := &d.nodes[index]
	if parent != nil {
		pn := &d.nodes[parent.index]
		if pn.major == 5 && parent.seen%2 == 0 {
			if node.major != 0 || node.n > d.registry.Encoding.MaxFieldID {
				return CBORFailure("field_id_type")
			}
			if parent.previousKey >= 0 {
				prev := d.nodes[parent.previousKey]
				a, b := d.input[prev.start:prev.end], d.input[node.start:node.end]
				order := bytes.Compare(a, b)
				if order == 0 {
					return CBORFailure("duplicate_key")
				}
				if len(a) > len(b) || len(a) == len(b) && order > 0 {
					return CBORFailure("map_order")
				}
			}
			parent.previousKey = index
		}
		if parent.previous < 0 {
			pn.first = index
		} else {
			d.nodes[parent.previous].next = index
		}
		parent.previous, parent.seen, parent.remaining = index, parent.seen+1, parent.remaining-1
	}
	if node.major == 4 || node.major == 5 {
		remaining := node.n
		if node.major == 4 {
			if node.n > d.registry.Encoding.OrdinaryArrayItems {
				return CBORFailure("array_limit")
			}
		} else {
			if node.n > d.registry.Encoding.MaxMapEntries {
				return CBORFailure("map_limit")
			}
			remaining *= 2
		}
		if remaining > uint64(d.size-c.pos) {
			return CBORFailure("truncated")
		}
		if c.depth == len(c.frames) {
			return CBORFailure("depth_limit")
		}
		c.frames[c.depth] = contractParseFrame{index: index, previous: -1, previousKey: -1, remaining: remaining, field: field}
		c.depth++
	}
	return nil
}

func (c *contractDecodeCursor) shape() error {
	if c.shaped == c.planned {
		c.phase = 2
		return nil
	}
	entry := c.plan[c.shaped]
	d := c.decoder
	f := entry.field
	// These private schema graphs have only integer-keyed maps, arrays and
	// bounded scalar fields. Embedded snapshot bodies are validated separately.
	if f == nil || f.Type == "context_variant" || f.Type == "text_map" || f.MaxItemsRef != "" || f.TextFormat != "" {
		return CBORFailure("configuration_capacity")
	}
	if f.EncodedSchemaRef != "" && !(d.snapshotEnvelope && entry.context.m == d.registry.Maps["ContractSnapshot"] && (f.EncodedSchemaRef == "ServiceContract" || f.EncodedSchemaRef == "AdmissionOffer")) {
		return CBORFailure("configuration_capacity")
	}
	n := d.nodes[entry.index]
	if (n.major == 2 || n.major == 3) && n.n > 4096 && (f.Nonzero || f.texts != nil || f.pattern != nil || f.ForbiddenPrefix != nil || f.constant != nil) {
		return CBORFailure("configuration_capacity")
	}
	var childContext *wireContext
	err := d.shapeStep(entry.index, f, entry.context, func(index int, child *wireField, context *wireContext) error {
		if c.planned == len(c.plan) {
			return CBORFailure("node_capacity")
		}
		if context != entry.context {
			if childContext == nil {
				if c.contextCount == len(c.contexts) {
					return CBORFailure("node_capacity")
				}
				childContext = &c.contexts[c.contextCount]
				*childContext = *context
				c.contextCount++
			}
			context = childContext
		}
		c.plan[c.planned] = contractShapeEntry{index, child, context}
		c.planned++
		return nil
	})
	if err == nil {
		c.shaped++
	}
	return err
}

func (c *contractDecodeCursor) rules() error {
	if c.ruleAt == c.planned {
		c.phase = 3
		return nil
	}
	entry := c.plan[c.ruleAt]
	if entry.field.Type != "map" {
		c.ruleAt++
		return nil
	}
	rules, err := runtimeRules()
	if err != nil {
		return err
	}
	groups := [3][]wireRule{rules.Variants[entry.field.SchemaRef], rules.Relations[entry.field.SchemaRef], rules.Text[entry.field.SchemaRef]}
	for c.ruleGroup < len(groups) && c.ruleIndex == len(groups[c.ruleGroup]) {
		c.ruleGroup++
		c.ruleIndex = 0
	}
	if c.ruleGroup == len(groups) {
		c.ruleGroup, c.ruleIndex = 0, 0
		c.ruleAt++
		return nil
	}
	rule := &groups[c.ruleGroup][c.ruleIndex]
	// The complete fixed graphs use scalar relations and bounded numeric array
	// rules (64 error codes or eight target indices). A future registry operation
	// needs its own step bound before it can run on the protected worker.
	switch rule.Op {
	case "variant", "less_or_equal", "increasing", "ordinal_indices":
	default:
		return CBORFailure("configuration_capacity")
	}
	context := wireContext{external: &c.context, parent: entry.context, m: c.decoder.registry.Maps[entry.field.SchemaRef], node: entry.index}
	if err := c.decoder.checkRule(entry.index, entry.field, &context, rule, rules); err != nil {
		return err
	}
	c.ruleIndex++
	return nil
}

func (c *contractDecodeCursor) step() (bool, error) {
	if c.decoder == nil {
		return false, CBORFailure("document_released")
	}
	var err error
	switch c.phase {
	case 0:
		err = c.parse()
	case 1:
		err = c.shape()
	case 2:
		err = c.rules()
	}
	return c.phase == 3 && err == nil, err
}

// take moves the validated borrowed document, never the underlying response.
func (c *contractDecodeCursor) take() *Document {
	if c.decoder == nil || c.phase != 3 {
		return nil
	}
	doc := c.document
	*c = contractDecodeCursor{}
	return doc
}
func (c *contractDecodeCursor) close() {
	if c.document != nil {
		c.document.Release()
	}
	*c = contractDecodeCursor{}
}
