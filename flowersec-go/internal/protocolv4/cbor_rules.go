package protocolv4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
)

// Rule descriptors consume the generated registry; no protocol field numbers,
// variants, carrier tuples or error policies are duplicated here.
type wireBranch struct {
	Absent, Required, Nonzero []string
	Constants                 map[string]any
	EnumValues                map[string][]uint64 `json:"enum_values"`
	Equal                     [][2]string
	LessOrEqual               [][2]string       `json:"less_or_equal"`
	ZeroBytes                 []string          `json:"zero_bytes"`
	ByteLengths               map[string]uint64 `json:"byte_lengths"`
	BytePrefixes              map[string]string `json:"byte_prefixes"`
	Registered                map[string]string
}
type wireRule struct {
	Op, Field, Left, Right, Profile, Algorithm, Registry, Source, Domain string
	Discriminator, Context, Feature, Format, Host, Port, Origin, Scheme  string
	When                                                                 *struct {
		Field, Context string
		Value          any
	}
	Fields           []string
	ItemField        string   `json:"item_field"`
	ItemFieldID      *uint64  `json:"item_field_id"`
	ItemFieldsJSON   []string `json:"item_fields"`
	Pairs, Rows      [][]uint64
	Min, Max         *wireBound
	Present          *bool
	Value            any
	Cases            map[string]wireBranch
	CodeField        string `json:"code_field"`
	TargetScopeField string `json:"target_scope_field"`
	StreamIDField    string `json:"stream_id_field"`
	RetryAfterField  string `json:"retry_after_field"`
	Selectors        []struct{ Field, Context string }
	wireBranch
}
type wireRules struct {
	Variants  map[string][]wireRule     `json:"variant_rules"`
	Relations map[string][]wireRule     `json:"relation_rules"`
	Text      map[string][]wireRule     `json:"text_rules"`
	Fields    map[string]map[string]any `json:"field_registries"`
}

var runtimeRules = sync.OnceValues(func() (*wireRules, error) {
	r := new(wireRules)
	d := json.NewDecoder(strings.NewReader(CBORSyntaxRegistryJSON))
	d.UseNumber()
	// Some field registry roots are constants, not tables.
	var raw struct {
		Variants  map[string][]wireRule `json:"variant_rules"`
		Relations map[string][]wireRule `json:"relation_rules"`
		Text      map[string][]wireRule `json:"text_rules"`
		Fields    map[string]any        `json:"field_registries"`
	}
	if err := d.Decode(&raw); err != nil {
		return nil, err
	}
	r.Variants, r.Relations, r.Text = raw.Variants, raw.Relations, raw.Text
	r.Fields = make(map[string]map[string]any)
	for name, value := range raw.Fields {
		if table, ok := value.(map[string]any); ok {
			r.Fields[name] = table
		}
	}
	return r, nil
})

// DecodeMap validates all registered stateless field, variant, relation and
// host/Origin rules. Signatures, cross-object admission, freshness and resource
// ownership still require their independent owners. Input bytes never change.
func (d *Decoder) DecodeMap(input []byte, schema string, context DecodeContext) (*Document, error) {
	doc, err := d.DecodeShape(input, schema, context)
	if err != nil {
		return nil, err
	}
	if err = doc.ValidateRules(context); err != nil {
		doc.Release()
		return nil, err
	}
	return doc, nil
}

func (doc *Document) ValidateRules(context DecodeContext) error {
	d := doc.decoder
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.active || d.generation != doc.generation {
		return CBORFailure("document_released")
	}
	if doc.schema == "" {
		return nil
	}
	r, err := runtimeRules()
	if err != nil {
		return err
	}
	return d.walkRules(doc.root, &wireField{Type: "map", SchemaRef: doc.schema}, &wireContext{external: &context}, r)
}

func (d *Decoder) rulePath(root int, field *wireField, path string, context *wireContext) (int, *wireField, error) {
	for path != "" && root >= 0 {
		part, rest, _ := strings.Cut(path, ".")
		path = rest
		if field.Type == "context_variant" {
			label, ok := d.selector(context, field.Context)
			if !ok || field.Cases[label] == nil {
				return -1, nil, CBORFailure("context_unresolved")
			}
			field = field.Cases[label]
		}
		if field.Type == "array" || field.Type == "array<uint64>" {
			index, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return -1, nil, CBORFailure("unknown_rule_field")
			}
			node := d.nodes[root]
			if index >= node.n {
				return -1, field.Items, nil
			}
			root = node.first
			for ; index > 0; index-- {
				root = d.nodes[root].next
			}
			field = field.Items
			continue
		}
		name := field.SchemaRef
		if field.EncodedSchemaRef != "" {
			name, root = field.EncodedSchemaRef, d.nodes[root].embedded
		}
		m := d.registry.Maps[name]
		if m == nil || root < 0 || d.nodes[root].major != 5 || m.byName[part] == nil {
			return -1, nil, CBORFailure("unknown_rule_field")
		}
		context = &wireContext{external: context.external, parent: context, m: m, node: root}
		field = m.byName[part]
		root = d.lookup(root, field.id)
	}
	return root, field, nil
}

func (d *Decoder) ruleBytes(index int, payload bool) []byte {
	if index < 0 {
		return nil
	}
	n := d.nodes[index]
	start := n.start
	if payload {
		start = n.dataStart
	}
	return d.input[start:n.end]
}
func ruleUint(value any) (uint64, bool) {
	v, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(string(v), 10, 64)
	return n, err == nil
}
func (d *Decoder) ruleEqualConstant(index int, value any) bool {
	if index < 0 {
		return false
	}
	n := d.nodes[index]
	switch v := value.(type) {
	case string:
		return n.major == 3 && string(d.ruleBytes(index, true)) == v
	case bool:
		return n.major == 7 && (n.n == 20 || n.n == 21) && (n.n == 21) == v
	case json.Number:
		number, ok := ruleUint(v)
		return ok && n.major == 0 && n.n == number
	}
	return false
}
func (d *Decoder) ruleEqual(a, b int) bool {
	if a < 0 || b < 0 {
		return a == b
	}
	return bytes.Equal(d.ruleBytes(a, false), d.ruleBytes(b, false))
}
func (d *Decoder) ruleCompare(a, b int) (int, error) {
	if a < 0 || b < 0 {
		return 0, CBORFailure("field_type")
	}
	x, y := d.nodes[a], d.nodes[b]
	if x.major == 0 && y.major == 0 {
		if x.n < y.n {
			return -1, nil
		}
		if x.n > y.n {
			return 1, nil
		}
		return 0, nil
	}
	if x.major == 2 && y.major == 2 {
		return bytes.Compare(d.ruleBytes(a, true), d.ruleBytes(b, true)), nil
	}
	return 0, CBORFailure("field_type")
}

func (d *Decoder) walkRules(index int, f *wireField, context *wireContext, rules *wireRules) error {
	if f.Type == "context_variant" {
		label, ok := d.selector(context, f.Context)
		if !ok || f.Cases[label] == nil {
			return CBORFailure("context_unresolved")
		}
		f = f.Cases[label]
	}
	n := d.nodes[index]
	if f.TextFormat != "" {
		if err := rules.textFormat(f.TextFormat, string(d.ruleBytes(index, true)), &d.idna); err != nil {
			return err
		}
	}
	if f.EncodedSchemaRef != "" && n.embedded >= 0 {
		return d.walkRules(n.embedded, &wireField{Type: "map", SchemaRef: f.EncodedSchemaRef}, context, rules)
	}
	switch f.Type {
	case "map":
		m := d.registry.Maps[f.SchemaRef]
		childContext := &wireContext{external: context.external, parent: context, m: m, node: index}
		for key := n.first; key >= 0; {
			value := d.nodes[key].next
			if err := d.walkRules(value, m.byID[d.nodes[key].n], childContext, rules); err != nil {
				return err
			}
			key = d.nodes[value].next
		}
		for _, group := range [][]wireRule{rules.Variants[f.SchemaRef], rules.Relations[f.SchemaRef], rules.Text[f.SchemaRef]} {
			for i := range group {
				if err := d.checkRule(index, f, childContext, &group[i], rules); err != nil {
					return err
				}
			}
		}
	case "array":
		for child := n.first; child >= 0; child = d.nodes[child].next {
			if err := d.walkRules(child, f.Items, context, rules); err != nil {
				return err
			}
		}
	case "text_map":
		for key := n.first; key >= 0; {
			value := d.nodes[key].next
			field := f.Values
			if f.Entries != nil {
				field = f.Entries[string(d.ruleBytes(key, true))]
			}
			if err := d.walkRules(value, field, context, rules); err != nil {
				return err
			}
			key = d.nodes[value].next
		}
	}
	return nil
}

func (d *Decoder) checkRule(root int, field *wireField, context *wireContext, rule *wireRule, rules *wireRules) error {
	var pathError error
	get := func(path string) int {
		n, _, err := d.rulePath(root, field, path, context)
		if err != nil {
			pathError = err
		}
		return n
	}
	if rule.When != nil {
		applies := false
		if rule.When.Context != "" {
			label, ok := d.selector(context, rule.When.Context)
			if !ok {
				return CBORFailure("context_unresolved")
			}
			applies = label == rule.When.Value
		} else {
			applies = d.ruleEqualConstant(get(rule.When.Field), rule.When.Value)
		}
		if pathError != nil {
			return pathError
		}
		if !applies {
			return nil
		}
	}
	u := func(index int) (uint64, bool) {
		if index < 0 {
			return 0, false
		}
		n := d.nodes[index]
		return n.n, n.major == 0
	}
	switch rule.Op {
	case "variant":
		if d.ruleEqualConstant(get(rule.Discriminator), rule.Value) {
			if err := d.checkBranch(get, rule.wireBranch, rules); err != nil {
				return err
			}
		}
	case "context_variant":
		label, ok := d.selector(context, rule.Context)
		branch, found := rule.Cases[label]
		if !ok || !found {
			return CBORFailure("context_unresolved")
		}
		if err := d.checkBranch(get, branch, rules); err != nil {
			return err
		}
	case "range":
		v, ok := u(get(rule.Field))
		if !ok || rule.Min == nil || rule.Max == nil || v < uint64(*rule.Min) || v > uint64(*rule.Max) {
			return CBORFailure("field_range")
		}
	case "is_null":
		v := get(rule.Field)
		if v < 0 || d.nodes[v].major != 7 || d.nodes[v].n != 22 {
			return CBORFailure("field_null")
		}
	case "at_least_one":
		found := false
		for _, f := range rule.Fields {
			found = get(f) >= 0 || found
		}
		if !found {
			return CBORFailure("field_presence")
		}
	case "equal", "equal_if_present", "not_equal":
		a, b := get(rule.Left), get(rule.Right)
		if rule.Op == "equal_if_present" && (a < 0 || b < 0) {
			break
		}
		equal := d.ruleEqual(a, b)
		if rule.Op == "not_equal" && equal {
			return CBORFailure("field_distinctness")
		}
		if rule.Op != "not_equal" && !equal {
			return CBORFailure("field_equality")
		}
	case "less_than", "less_or_equal", "max_difference", "bit_subset":
		a, aok := u(get(rule.Left))
		b, bok := u(get(rule.Right))
		if !aok || !bok {
			return CBORFailure("integer_type")
		}
		switch rule.Op {
		case "less_than", "less_or_equal":
			if a > b || rule.Op == "less_than" && a == b {
				return CBORFailure("field_order")
			}
		case "max_difference":
			if rule.Max == nil {
				return CBORFailure("rule_unresolved")
			}
			if a > b || b-a > uint64(*rule.Max) {
				return CBORFailure("field_duration")
			}
		case "bit_subset":
			if a & ^b != 0 {
				return CBORFailure("feature_subset")
			}
		}
	case "allowed_pairs", "allowed_tuples":
		fields, rows := rule.Fields, rule.Rows
		if rule.Op == "allowed_pairs" {
			fields, rows = []string{rule.Left, rule.Right}, rule.Pairs
		}
		found := false
		for _, row := range rows {
			if len(row) != len(fields) {
				return CBORFailure("rule_unresolved")
			}
			match := true
			for i, f := range fields {
				v, ok := u(get(f))
				match = match && ok && v == row[i]
			}
			found = found || match
		}
		if !found {
			return CBORFailure("field_tuple")
		}
	case "feature_bit":
		entry, _ := rules.Fields["feature_registry"][rule.Feature].(map[string]any)
		bit, ok := ruleUint(entry["bit"])
		if !ok || bit >= 64 || rule.Present == nil {
			return CBORFailure("registry_unresolved")
		}
		v, ok := u(get(rule.Field))
		if !ok {
			return CBORFailure("integer_type")
		}
		if (v&(uint64(1)<<bit) != 0) != *rule.Present {
			return CBORFailure("feature_policy")
		}
	case "profile_algorithm":
		profile := get(rule.Profile)
		if profile < 0 || d.nodes[profile].major != 3 {
			return CBORFailure("field_type")
		}
		entry, _ := rules.Fields["crypto_profiles"][string(d.ruleBytes(profile, true))].(map[string]any)
		algorithm, ok := ruleUint(entry["dh_algorithm"])
		if !ok {
			return CBORFailure("registry_unresolved")
		}
		v, ok := u(get(rule.Algorithm))
		if !ok || v != algorithm {
			return CBORFailure("profile_algorithm")
		}
	case "registry_tuple":
		tuple := rules.Fields[rule.Registry]
		for _, s := range rule.Selectors {
			key := ""
			if s.Context != "" {
				key, _ = d.selector(context, s.Context)
			} else {
				v, ok := u(get(s.Field))
				if ok {
					for label, n := range d.registry.Maps[field.SchemaRef].byName[s.Field].Enum {
						if v == n {
							key = label
						}
					}
				}
			}
			next, ok := tuple[key].(map[string]any)
			if key == "" || !ok {
				return CBORFailure("context_unresolved")
			}
			tuple = next
		}
		for _, f := range rule.Fields {
			v := get(f)
			if tuple[f] == nil && v < 0 {
				continue
			}
			if !d.ruleEqualConstant(v, tuple[f]) {
				return CBORFailure("carrier_tuple")
			}
		}
	case "map_digest":
		source, spec, err := d.rulePath(root, field, rule.Source, context)
		if err != nil {
			return err
		}
		target := get(rule.Field)
		if source < 0 || target < 0 || d.nodes[target].major != 2 {
			return CBORFailure("field_type")
		}
		name, encoded := spec.SchemaRef, d.ruleBytes(source, false)
		if spec.EncodedSchemaRef != "" {
			name, encoded = spec.EncodedSchemaRef, d.ruleBytes(source, true)
		}
		digest, err := fullMapDigest(rule.Domain, name, encoded)
		if err != nil {
			return err
		}
		if !bytes.Equal(digest[:], d.ruleBytes(target, true)) {
			return CBORFailure("map_digest_mismatch")
		}
	case "error_scope":
		label := ""
		code := get(rule.CodeField)
		for name, n := range rules.Fields["error_codes"] {
			if d.ruleEqualConstant(code, n) {
				label = name
			}
		}
		policy, ok := rules.Fields["error_code_metadata"][label].(map[string]any)
		if !ok {
			return CBORFailure("enum_value")
		}
		target, tok := u(get(rule.TargetScopeField))
		stream := get(rule.StreamIDField)
		if !tok {
			return CBORFailure("error_scope")
		}
		switch policy["scope"] {
		case "session":
			if target != 0 || stream >= 0 {
				return CBORFailure("error_scope")
			}
		case "stream":
			s, ok := u(stream)
			if !ok || target == 0 || s != target {
				return CBORFailure("error_scope")
			}
		default:
			return CBORFailure("registry_unresolved")
		}
		if policy["retryable"] != true && get(rule.RetryAfterField) >= 0 {
			return CBORFailure("retry_after_forbidden")
		}
	case "unique_by", "increasing_tuple", "ordinal_indices", "increasing", "increasing_bytes", "increasing_cbor", "increasing_scopes", "exclusive_item":
		if err := d.checkArrayRule(root, field, context, rule); err != nil {
			return err
		}
	case "text_format":
		v := get(rule.Field)
		if v < 0 || d.nodes[v].major != 3 {
			return CBORFailure("field_type")
		}
		if err := rules.textFormat(rule.Format, string(d.ruleBytes(v, true)), &d.idna); err != nil {
			return err
		}
	case "origin_endpoint":
		host, origin := get(rule.Host), get(rule.Origin)
		port, ok := u(get(rule.Port))
		if !ok || host < 0 || origin < 0 {
			return CBORFailure("field_type")
		}
		h := string(d.ruleBytes(host, true))
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		standard, err := rules.originDefaultPort(rule.Scheme)
		if err != nil {
			return err
		}
		expected := rule.Scheme + "://" + h
		if port != standard {
			expected += ":" + strconv.FormatUint(port, 10)
		}
		if string(d.ruleBytes(origin, true)) != expected {
			return CBORFailure("origin_endpoint")
		}
	default:
		return CBORFailure("rule_unresolved")
	}
	return pathError
}

func (d *Decoder) checkBranch(get func(string) int, b wireBranch, r *wireRules) error {
	for _, p := range b.Absent {
		if get(p) >= 0 {
			return CBORFailure("variant_absent")
		}
	}
	for _, p := range b.Required {
		if get(p) < 0 {
			return CBORFailure("variant_required")
		}
	}
	for p, v := range b.Constants {
		if !d.ruleEqualConstant(get(p), v) {
			return CBORFailure("variant_constant")
		}
	}
	for p, allowed := range b.EnumValues {
		v := get(p)
		found := false
		if v >= 0 && d.nodes[v].major == 0 {
			for _, n := range allowed {
				found = found || d.nodes[v].n == n
			}
		}
		if !found {
			return CBORFailure("enum_value")
		}
	}
	for _, pair := range b.Equal {
		if !d.ruleEqual(get(pair[0]), get(pair[1])) {
			return CBORFailure("field_equality")
		}
	}
	for _, pair := range b.LessOrEqual {
		a, b := get(pair[0]), get(pair[1])
		if a < 0 || b < 0 || d.nodes[a].major != 0 || d.nodes[b].major != 0 || d.nodes[a].n > d.nodes[b].n {
			return CBORFailure("field_order")
		}
	}
	for _, p := range b.Nonzero {
		v := get(p)
		nonzero := false
		if v >= 0 {
			n := d.nodes[v]
			if n.major == 0 {
				nonzero = n.n != 0
			}
			if n.major == 2 {
				for _, x := range d.ruleBytes(v, true) {
					nonzero = nonzero || x != 0
				}
			}
		}
		if !nonzero {
			return CBORFailure("variant_nonzero")
		}
	}
	for _, p := range b.ZeroBytes {
		v := get(p)
		if v < 0 || d.nodes[v].major != 2 {
			return CBORFailure("variant_zero_bytes")
		}
		for _, x := range d.ruleBytes(v, true) {
			if x != 0 {
				return CBORFailure("variant_zero_bytes")
			}
		}
	}
	for p, length := range b.ByteLengths {
		v := get(p)
		if v < 0 || d.nodes[v].major != 2 || d.nodes[v].n != length {
			return CBORFailure("field_length")
		}
	}
	for p, prefix := range b.BytePrefixes {
		v := get(p)
		raw, err := hex.DecodeString(prefix)
		if err != nil {
			return CBORFailure("registry_unresolved")
		}
		if v < 0 || d.nodes[v].major != 2 || !bytes.HasPrefix(d.ruleBytes(v, true), raw) {
			return CBORFailure("field_prefix")
		}
	}
	for p, table := range b.Registered {
		found := false
		v := get(p)
		for _, raw := range r.Fields[table] {
			if entry, ok := raw.(map[string]any); ok {
				raw = entry["code"]
			}
			found = found || d.ruleEqualConstant(v, raw)
		}
		if !found {
			return CBORFailure("enum_value")
		}
	}
	return nil
}

func (d *Decoder) checkArrayRule(root int, field *wireField, context *wireContext, rule *wireRule) error {
	array, spec, err := d.rulePath(root, field, rule.Field, context)
	if err != nil {
		return err
	}
	if array < 0 && (rule.Op == "increasing_bytes" || rule.Op == "increasing_cbor") {
		return nil
	}
	if array < 0 || d.nodes[array].major != 4 {
		return CBORFailure("field_type")
	}
	// Unique tuples compare bounded original nodes directly, with no peer-sized
	// hash table or re-encoding. All large history arrays use ordered rules.
	itemFields := rule.ItemFieldsJSON
	var scopeMax uint64
	if rule.Op == "increasing_scopes" {
		r, err := runtimeRules()
		if err != nil {
			return err
		}
		entry, _ := r.Fields["resource_caps"]["scope_id"].(map[string]any)
		text, ok := entry["max"].(string)
		if !ok {
			return CBORFailure("registry_unresolved")
		}
		scopeMax, err = strconv.ParseUint(text, 10, 64)
		if err != nil {
			return CBORFailure("registry_unresolved")
		}
	}
	previous, index := -1, uint64(0)
	for item := d.nodes[array].first; item >= 0; item = d.nodes[item].next {
		current := item
		if rule.ItemFieldID != nil {
			current = d.lookup(item, *rule.ItemFieldID)
		}
		if current < 0 {
			return CBORFailure("unknown_rule_field")
		}
		switch rule.Op {
		case "unique_by", "increasing_tuple":
			start := d.nodes[array].first
			if rule.Op == "increasing_tuple" {
				start = previous
			}
			for prior := start; prior >= 0 && prior != item; prior = d.nodes[prior].next {
				order := 0
				for _, path := range itemFields {
					a, _, err := d.rulePath(prior, spec.Items, path, context)
					if err != nil {
						return err
					}
					b, _, err := d.rulePath(item, spec.Items, path, context)
					if err != nil {
						return err
					}
					if a < 0 || b < 0 {
						return CBORFailure("unknown_rule_field")
					}
					if rule.Op == "unique_by" {
						if !d.ruleEqual(a, b) {
							order = 1
							break
						}
					} else {
						order, err = d.ruleCompare(a, b)
						if err != nil {
							return err
						}
						if order != 0 {
							break
						}
					}
				}
				if rule.Op == "unique_by" && order == 0 {
					return CBORFailure("item_identity")
				}
				if rule.Op == "increasing_tuple" && order >= 0 {
					return CBORFailure("item_order")
				}
			}
		case "ordinal_indices":
			if d.nodes[current].major != 0 || d.nodes[current].n != index {
				return CBORFailure("item_index")
			}
		case "increasing", "increasing_scopes":
			if d.nodes[current].major != 0 {
				return CBORFailure("integer_type")
			}
			if rule.Op == "increasing_scopes" && (d.nodes[current].n == 0 || d.nodes[current].n > scopeMax) {
				return CBORFailure("scope_order")
			}
			if previous >= 0 {
				p := previous
				if rule.ItemFieldID != nil {
					p = d.lookup(p, *rule.ItemFieldID)
				}
				if d.nodes[current].n <= d.nodes[p].n {
					return CBORFailure("item_order")
				}
			}
		case "increasing_bytes", "increasing_cbor":
			payload := rule.Op == "increasing_bytes"
			if payload && d.nodes[current].major != 2 {
				return CBORFailure("field_type")
			}
			if previous >= 0 {
				p := previous
				if rule.ItemFieldID != nil {
					p = d.lookup(p, *rule.ItemFieldID)
				}
				if bytes.Compare(d.ruleBytes(p, payload), d.ruleBytes(current, payload)) >= 0 {
					return CBORFailure("item_order")
				}
			}
		case "exclusive_item":
			v, _, err := d.rulePath(item, spec.Items, rule.ItemField, context)
			if err != nil {
				return err
			}
			if d.ruleEqualConstant(v, rule.Value) && d.nodes[array].n != 1 {
				return CBORFailure("item_exclusive")
			}
		}
		previous = item
		index++
	}
	return nil
}
