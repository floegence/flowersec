package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type domainFixture struct {
	ID, Domain    string
	Inputs        map[string]json.RawMessage
	Context       map[string]json.RawMessage
	ExpectedError string `json:"expected_error"`
	Result        struct {
		Label        string  `json:"label_hex"`
		Input        string  `json:"input_hex"`
		Output       string  `json:"output_hex"`
		Salt         string  `json:"salt_hex"`
		IKM          string  `json:"ikm_hex"`
		OutputLength *uint64 `json:"output_length"`
	}
}

func domainFixtures(t testing.TB) []domainFixture {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v4/domains.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaSHA string `json:"schema_sha256"`
		Vectors   []domainFixture
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaSHA != SchemaSHA256 {
		t.Fatal("domain corpus schema drift")
	}
	return corpus.Vectors
}

func domainHex(t testing.TB, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (v domainFixture) args(t testing.TB) map[string]any {
	t.Helper()
	args := map[string]any{}
	for name, raw := range v.Inputs {
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		if object, ok := value.(map[string]any); ok {
			if text, ok := object["$bytes"].(string); ok {
				value = domainHex(t, text)
			} else if text, ok := object["$uint"].(string); ok {
				n, valid := new(big.Int).SetString(text, 10)
				if !valid {
					t.Fatal("invalid integer fixture")
				}
				if n.IsUint64() {
					value = n.Uint64()
				} else {
					// Preserve overflowing negative fixtures for the domain gate.
					value = n
				}
			} else {
				t.Fatal("unknown domain fixture type")
			}
		}
		args[name] = value
	}
	return args
}

func cloneDomainArgs(args map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range args {
		if raw, ok := value.([]byte); ok {
			value = bytes.Clone(raw)
		}
		result[key] = value
	}
	return result
}

func requireDomainFailure(t testing.TB, err error, code string) {
	t.Helper()
	if _, ok := err.(cborRefError); !ok {
		t.Fatalf("expected bounded domain/CBOR failure, got %v", err)
	}
	if code != "" && err.Error() != code {
		t.Fatalf("got %s, want %s", err, code)
	}
}

// v4.go_domains.corpus
func TestCBORDomainCorpus(t *testing.T) {
	r := newDomainReference(t)
	positive, negative := 0, 0
	covered := map[string]bool{}
	for _, fixture := range domainFixtures(t) {
		t.Run(fixture.ID, func(t *testing.T) {
			args, context := fixture.args(t), shapeContext(fixture.Context)
			before := cloneDomainArgs(args)
			contextBefore, _ := json.Marshal(context.selectors)
			result, err := r.evaluate(fixture.Domain, args, context, 1<<20)
			if fixture.ExpectedError != "" {
				negative++
				code := ""
				if strings.HasPrefix(fixture.ExpectedError, "domain_") {
					code = fixture.ExpectedError
				}
				requireDomainFailure(t, err, code)
			} else {
				positive++
				covered[fixture.Domain] = true
				if err != nil {
					t.Fatal(err)
				}
				for _, pair := range []struct {
					got  []byte
					want string
				}{{result.Label, fixture.Result.Label}, {result.Input, fixture.Result.Input}, {result.Output, fixture.Result.Output}, {result.Salt, fixture.Result.Salt}, {result.IKM, fixture.Result.IKM}} {
					if !bytes.Equal(pair.got, domainHex(t, pair.want)) {
						t.Fatal("domain bytes differ from shared vector")
					}
				}
				if !reflect.DeepEqual(result.OutputLength, fixture.Result.OutputLength) {
					t.Fatal("exporter output length drift")
				}
			}
			contextAfter, _ := json.Marshal(context.selectors)
			if !reflect.DeepEqual(args, before) || !bytes.Equal(contextBefore, contextAfter) {
				t.Fatal("caller input or context mutated")
			}
		})
	}
	if positive != 107 || negative != 52 || len(covered) != 58 {
		t.Fatalf("coverage %d/%d/%d", positive, negative, len(covered))
	}
	for name := range r.domains {
		if !covered[name] {
			t.Fatalf("uncovered domain %s", name)
		}
	}
}

// v4.go_domains.signing_inputs
func TestCBORDomainSigningInputs(t *testing.T) {
	r := newDomainReference(t)
	fixtures := map[string]domainFixture{}
	for _, fixture := range domainFixtures(t) {
		fixtures[fixture.ID] = fixture
	}
	raw, err := os.ReadFile("../../../testdata/transport_v4/signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Seed    string `json:"signing_seed_hex"`
		Vectors []struct {
			Domain       string
			DomainVector string `json:"domain_vector"`
			Message      string `json:"message_hex"`
			Public       string `json:"public_key_hex"`
			Signature    string `json:"signature_hex"`
			Accept       bool
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(domainHex(t, corpus.Seed))
	covered := map[string]bool{}
	for _, vector := range corpus.Vectors {
		if !vector.Accept || vector.DomainVector == "" {
			continue
		}
		fixture, ok := fixtures[vector.DomainVector]
		if !ok {
			t.Fatal("missing signature domain input")
		}
		result, err := r.evaluate(vector.Domain, fixture.args(t), shapeContext(fixture.Context), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if result.Output != nil || !bytes.Equal(result.Input, domainHex(t, vector.Message)) {
			t.Fatal("reconstructed signing input drift")
		}
		signature := ed25519.Sign(key, result.Input)
		if !bytes.Equal(signature, domainHex(t, vector.Signature)) || !ed25519.Verify(domainHex(t, vector.Public), result.Input, signature) {
			t.Fatal("real fixture signature differs")
		}
		covered[vector.Domain] = true
	}
	for name, domain := range r.domains {
		if domain.Operation == "ed25519" && !covered[name] {
			t.Fatalf("uncovered signing domain %s", name)
		}
	}
}

// v4.go_domains.arguments
func TestCBORDomainArguments(t *testing.T) {
	r := newDomainReference(t)
	visited := map[string]bool{}
	_, err := r.evaluate("unregistered", nil, cborShapeContext{}, 1<<20)
	requireDomainFailure(t, err, "domain_unknown")
	for _, fixture := range domainFixtures(t) {
		if fixture.ExpectedError != "" || visited[fixture.Domain] {
			continue
		}
		visited[fixture.Domain] = true
		args, ctx := fixture.args(t), shapeContext(fixture.Context)
		for _, missing := range []map[string]any{nil, {}, cloneDomainArgs(args)} {
			if len(missing) > 0 {
				missing["extra"] = []byte{}
			}
			_, err := r.evaluate(fixture.Domain, missing, ctx, 1<<20)
			requireDomainFailure(t, err, "domain_arguments")
		}
		for key := range args {
			changed := cloneDomainArgs(args)
			delete(changed, key)
			_, err := r.evaluate(fixture.Domain, changed, ctx, 1<<20)
			requireDomainFailure(t, err, "domain_arguments")
			changed[key] = nil
			_, err = r.evaluate(fixture.Domain, changed, ctx, 1<<20)
			requireDomainFailure(t, err, "")
		}
	}
}

// v4.go_domains.projections
func TestCBORDomainProjectionAndOwnership(t *testing.T) {
	r := newDomainReference(t)
	exclusions, full, raw := 0, 0, 0
	for _, fixture := range domainFixtures(t) {
		if fixture.ExpectedError != "" {
			continue
		}
		args, ctx := fixture.args(t), shapeContext(fixture.Context)
		original, err := r.evaluate(fixture.Domain, args, ctx, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range r.domains[fixture.Domain].Input.Parts {
			if part.Encoding != "lp-map" {
				continue
			}
			name := part.SchemaRef
			if name == "" {
				selector, _ := domainInteger(args[part.Selector])
				name = part.SchemaCases[strconv.FormatUint(selector, 10)]
			}
			value, err := r.wireMap(args[part.Name].([]byte), name, ctx, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			definition := r.registry.Maps[name]
			id := definition.SignatureField
			if part.Projection == "without_mac" {
				id = definition.MACField
			}
			if id == nil {
				continue
			}
			field := cborLookup(value, *id)
			if field == nil || field.major != 2 || len(field.data) == 0 {
				t.Fatal("projection fixture")
			}
			field.data = bytes.Clone(field.data)
			field.data[0] ^= 1
			changed := cloneDomainArgs(args)
			changed[part.Name] = value.encode(nil)
			result, err := r.evaluate(fixture.Domain, changed, ctx, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if part.Projection == "full" {
				full++
				if bytes.Equal(result.Input, original.Input) {
					t.Fatal("full projection omitted signature")
				}
			} else {
				exclusions++
				if !reflect.DeepEqual(result, original) {
					t.Fatal("excluded signature/MAC changed input")
				}
			}
		}
		if fixture.Domain == "topup_request_digest" || fixture.Domain == "topup_response_digest" {
			raw++
			if len(original.Label) != 0 {
				t.Fatal("raw TopUp gained a domain label")
			}
			if _, _, err := r.decode(original.Input, "", nil, 1<<20); err != nil {
				t.Fatal("raw TopUp gained a length prefix", err)
			}
		}
		detached, err := r.evaluate(fixture.Domain, args, ctx, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range args {
			if b, ok := value.([]byte); ok {
				clear(b)
			}
		}
		if !reflect.DeepEqual(detached, original) {
			t.Fatal("result retained input backing")
		}
	}
	if exclusions == 0 || full == 0 || raw != 2 {
		t.Fatalf("missing projection coverage %d/%d/%d", exclusions, full, raw)
	}
}

// v4.go_domains.widths_and_exporters
func TestCBORDomainWidthsAndExporters(t *testing.T) {
	r := newDomainReference(t)
	maximum, err := domainUnsigned(uint64(math.MaxUint64), 8)
	if err != nil || !bytes.Equal(maximum, bytes.Repeat([]byte{255}, 8)) {
		t.Fatal("UInt64 maximum lost")
	}
	for _, width := range []int{1, 4, 8} {
		for _, bad := range []any{float64(-1), 1.5, math.NaN(), math.Inf(1), float64(9007199254740992), "1", true, big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 64)} {
			_, err := domainUnsigned(bad, width)
			requireDomainFailure(t, err, "")
		}
		if width < 8 {
			_, err := domainUnsigned(uint64(1)<<(width*8), width)
			requireDomainFailure(t, err, "domain_integer_range")
		}
	}
	for _, fixture := range domainFixtures(t) {
		if fixture.ExpectedError != "" || !strings.HasPrefix(fixture.Domain, "tls_exporter_") {
			continue
		}
		args, ctx := fixture.args(t), shapeContext(fixture.Context)
		result, err := r.evaluate(fixture.Domain, args, ctx, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if result.Output != nil || result.OutputLength == nil || *result.OutputLength != 32 {
			t.Fatal("exporter claimed live output")
		}
		if fixture.Domain == "tls_exporter_raw" {
			if string(result.Label) != "EXPORTER-flowersec-v4" || len(result.Label) != 21 || len(result.Input) != 32 {
				t.Fatal("raw exporter drift")
			}
		} else {
			expected := append([]byte{21}, []byte("EXPORTER-flowersec-v4")...)
			expected = append(expected, 32)
			if string(result.Label) != "EXPORTER-WebTransport" || len(result.Input) != 63 || !bytes.Equal(result.Input[8:31], expected) {
				t.Fatal("WT context drift")
			}
			args["connect_stream_id"] = uint64(1<<62) - 4
			result, err := r.evaluate(fixture.Domain, args, ctx, 1<<20)
			if err != nil || !bytes.Equal(result.Input[:8], domainHex(t, "3ffffffffffffffc")) {
				t.Fatal("WT stream maximum lost", err)
			}
			for _, id := range []uint64{1, 1<<62 - 1, 1 << 62} {
				args["connect_stream_id"] = id
				_, err := r.evaluate(fixture.Domain, args, ctx, 1<<20)
				requireDomainFailure(t, err, "")
			}
		}
	}
}

// v4.go_domains.properties
func TestCBORDomainMutationProperties(t *testing.T) {
	r := newDomainReference(t)
	positives := []domainFixture{}
	for _, fixture := range domainFixtures(t) {
		if fixture.ExpectedError == "" {
			positives = append(positives, fixture)
		}
	}
	state := uint64(0x41d041d041d041d0)
	next := func() uint64 { state = state*6364136223846793005 + 1442695040888963407; return state ^ state>>31 }
	for range 4096 {
		fixture := positives[next()%uint64(len(positives))]
		args, ctx := fixture.args(t), shapeContext(fixture.Context)
		// Sorted source JSON names give deterministic mutation selection.
		keys := make([]string, 0, len(args))
		for name := range args {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		key := keys[next()%uint64(len(keys))]
		switch value := args[key].(type) {
		case []byte:
			if len(value) > 0 {
				value[next()%uint64(len(value))] ^= byte(next())
			}
		case float64:
			args[key] = uint64(value) ^ next()
		case uint64:
			args[key] = value ^ next()
		case string:
			args[key] = value + "x"
		}
		before := cloneDomainArgs(args)
		contextBefore, _ := json.Marshal(ctx.selectors)
		result, err := r.evaluate(fixture.Domain, args, ctx, 1<<20)
		if !reflect.DeepEqual(args, before) {
			t.Fatal("input mutated")
		}
		if err != nil {
			requireDomainFailure(t, err, "")
		} else {
			repeat, err := r.evaluate(fixture.Domain, args, ctx, 1<<20)
			if err != nil || !reflect.DeepEqual(repeat, result) {
				t.Fatal("nondeterministic domain result", err)
			}
			snapshot := *result
			snapshot.Label, snapshot.Input, snapshot.Output = bytes.Clone(result.Label), bytes.Clone(result.Input), bytes.Clone(result.Output)
			snapshot.Salt, snapshot.IKM = bytes.Clone(result.Salt), bytes.Clone(result.IKM)
			for _, value := range args {
				if raw, ok := value.([]byte); ok {
					clear(raw)
				}
			}
			if !reflect.DeepEqual(&snapshot, result) {
				t.Fatal("result alias")
			}
		}
		contextAfter, _ := json.Marshal(ctx.selectors)
		if !bytes.Equal(contextBefore, contextAfter) {
			t.Fatal("context mutation")
		}
	}
}
