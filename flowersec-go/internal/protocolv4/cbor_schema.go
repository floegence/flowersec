package protocolv4

import (
	"encoding/json"
	"regexp"
	"strconv"
	"sync"
)

type wireBound uint64

func (b *wireBound) UnmarshalJSON(raw []byte) error {
	text := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
	}
	n, err := strconv.ParseUint(text, 10, 64)
	*b = wireBound(n)
	return err
}

// These descriptors are loaded once from the generated contract. They are not
// an additional field registry, and no peer can supply or extend them.
type wireField struct {
	Name, Type, Context       string
	SchemaRef                 string `json:"schema_ref"`
	EncodedSchemaRef          string `json:"encoded_schema_ref"`
	AllowEmpty                bool   `json:"allow_empty"`
	Nullable, Nonzero         bool
	Min, Max, Length, Bitmask *wireBound
	MinBytes                  *wireBound `json:"min_bytes"`
	MaxBytes                  *wireBound `json:"max_bytes"`
	MinItems                  *wireBound `json:"min_items"`
	MaxItems                  *wireBound `json:"max_items"`
	MaxItemsRef               string     `json:"max_items_ref"`
	MaxRef                    string     `json:"max_ref"`
	Items, Values, Keys       *wireField
	Entries, Cases            map[string]*wireField
	Const                     json.RawMessage
	ConstRef                  string `json:"const_ref"`
	Enum                      map[string]uint64
	EnumRef                   string  `json:"enum_ref"`
	TextEnumRef               string  `json:"text_enum_ref"`
	PatternRef                string  `json:"pattern_ref"`
	TextFormat                string  `json:"text_format"`
	ForbiddenPrefix           *string `json:"forbidden_prefix"`
	ProfilePublicKey          bool    `json:"profile_public_key"`

	id       uint64
	width    int
	enums    map[uint64]bool
	texts    map[string]bool
	constant *wireConstant
	pattern  *regexp.Regexp
}

type wireConstant struct {
	major byte
	n     uint64
	text  string
}

type wireMap struct {
	MACField           *uint64 `json:"mac_field"`
	SignatureField     *uint64 `json:"signature_field"`
	SenderRole         *uint64 `json:"sender_role"`
	Fields             map[string]*wireField
	Required           []uint64
	ContextFields      map[string]string `json:"context_fields"`
	MaxEncodedBytes    *uint64           `json:"max_encoded_bytes"`
	EncodedBytes       *uint64           `json:"encoded_bytes"`
	MaxEncodedBytesRef string            `json:"max_encoded_bytes_ref"`
	byID               map[uint64]*wireField
	byName             map[string]*wireField
}

type wireRegistry struct {
	Encoding struct {
		MaxDepth           int    `json:"max_depth"`
		MaxMapEntries      uint64 `json:"max_map_entries"`
		OrdinaryArrayItems uint64 `json:"ordinary_array_items"`
		MaxFieldID         uint64 `json:"max_field_id"`
	}
	Maps           map[string]*wireMap        `json:"frame_maps"`
	Fields         map[string]json.RawMessage `json:"field_registries"`
	MapProjections map[string]struct {
		Source, Target string
		Fields         []string
	} `json:"map_projections"`
}

var runtimeSchema = sync.OnceValues(func() (*wireRegistry, error) {
	r := new(wireRegistry)
	if err := json.Unmarshal([]byte(CBORSyntaxRegistryJSON), r); err != nil {
		return nil, err
	}
	for _, m := range r.Maps {
		m.byID = make(map[uint64]*wireField, len(m.Fields))
		m.byName = make(map[string]*wireField, len(m.Fields))
		for id, f := range m.Fields {
			n, err := strconv.ParseUint(id, 10, 16)
			if err != nil {
				return nil, err
			}
			f.id = n
			m.byID[n] = f
			m.byName[f.Name] = f
			if err := r.compile(f); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
})

func (r *wireRegistry) compile(f *wireField) error {
	if f == nil {
		return nil
	}
	switch f.Type {
	case "uint8":
		f.width = 8
	case "uint16":
		f.width = 16
	case "uint32":
		f.width = 32
	case "uint64":
		f.width = 64
	}
	if f.Enum != nil {
		f.enums = make(map[uint64]bool, len(f.Enum))
		for _, n := range f.Enum {
			f.enums[n] = true
		}
	}
	if f.EnumRef != "" || f.TextEnumRef != "" {
		ref := f.EnumRef
		if ref == "" {
			ref = f.TextEnumRef
		}
		var entries map[string]json.RawMessage
		if json.Unmarshal(r.Fields[ref], &entries) != nil || len(entries) == 0 {
			return CBORFailure("registry_unresolved")
		}
		if f.TextEnumRef != "" {
			f.texts = make(map[string]bool, len(entries))
			for text := range entries {
				f.texts[text] = true
			}
		} else {
			f.enums = make(map[uint64]bool, len(entries))
			f.Enum = make(map[string]uint64, len(entries))
			for name, raw := range entries {
				if len(raw) > 0 && raw[0] == '{' {
					var v struct{ Code json.RawMessage }
					if json.Unmarshal(raw, &v) != nil {
						return CBORFailure("registry_unresolved")
					}
					raw = v.Code
				}
				var n wireBound
				if json.Unmarshal(raw, &n) != nil {
					return CBORFailure("registry_unresolved")
				}
				f.enums[uint64(n)] = true
				f.Enum[name] = uint64(n)
			}
		}
	}
	raw := f.Const
	if f.ConstRef != "" {
		raw = r.Fields[f.ConstRef]
		if len(raw) == 0 {
			return CBORFailure("registry_unresolved")
		}
	}
	if len(raw) > 0 {
		v := new(wireConstant)
		switch f.Type {
		case "bytes", "text":
			v.major = 2
			if f.Type == "text" {
				v.major = 3
			}
			if json.Unmarshal(raw, &v.text) != nil {
				return CBORFailure("registry_unresolved")
			}
		case "bool":
			v.major = 7
			var b bool
			if json.Unmarshal(raw, &b) != nil {
				return CBORFailure("registry_unresolved")
			}
			v.n = 20
			if b {
				v.n = 21
			}
		default:
			var n wireBound
			if json.Unmarshal(raw, &n) != nil {
				return CBORFailure("registry_unresolved")
			}
			v.n = uint64(n)
		}
		f.constant = v
	}
	if f.PatternRef != "" {
		var patterns map[string]string
		if json.Unmarshal(r.Fields["text_patterns"], &patterns) != nil {
			return CBORFailure("registry_unresolved")
		}
		pattern, ok := patterns[f.PatternRef]
		if !ok {
			return CBORFailure("registry_unresolved")
		}
		var err error
		f.pattern, err = regexp.Compile("\\A(?:" + pattern + ")\\z")
		if err != nil {
			return err
		}
	}
	for _, child := range []*wireField{f.Items, f.Values, f.Keys} {
		if err := r.compile(child); err != nil {
			return err
		}
	}
	for _, entries := range []map[string]*wireField{f.Entries, f.Cases} {
		for _, child := range entries {
			if err := r.compile(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// FieldID resolves a field name in the sole generated registry. Unknown names
// are configuration errors; callers never assign their own numeric fields.
func FieldID(schema, name string) (uint64, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	m := r.Maps[schema]
	if m == nil || m.byName[name] == nil {
		return 0, CBORFailure("unknown_schema_field")
	}
	return m.byName[name].id, nil
}
