package protocolv4

import (
	"bytes"
	"strings"
	"testing"
)

var benchmarkSchemaDecoder *Decoder

func BenchmarkFixedSchemaDecoderConstruction(b *testing.B) {
	for _, schema := range []string{"ClientHello", "Artifact", "IdentityCertificate"} {
		b.Run(schema, func(b *testing.B) {
			maximum, err := SchemaByteLimit(schema)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				benchmarkSchemaDecoder, err = newSchemaDecoder(schema, maximum, maximum)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestRuntimeFixedSchemaDecoderRetainsMaximumTextAndOriginalArenas(t *testing.T) {
	for _, test := range []struct{ schema, fixture string }{
		{"FreshnessHead", "freshness_head_fields"},
		{"HeadSignerDelegation", "head_delegation_fields"},
	} {
		t.Run(test.schema, func(t *testing.T) {
			r := newCBORTextReference(t)
			seed := oracleSeed(t, test.fixture)
			root, _, err := r.decode(oracleBytes(t, seed.Hex), test.schema, nil, 1<<16)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"schema_revision", "tenant_id", "revocation_authority_id", "publication_policy_id"} {
				oracleField(t, r.cborReference, test.schema, root, field).data = []byte(strings.Repeat("a", 128))
			}
			wire := root.encode(nil)
			maximum, err := SchemaByteLimit(test.schema)
			if err != nil {
				t.Fatal(err)
			}
			d, err := newSchemaDecoder(test.schema, maximum, maximum)
			if err != nil {
				t.Fatal(err)
			}
			if d.byteLimit != maximum || d.input != nil || d.nodeLimit != maximum || d.nodes != nil {
				t.Fatal("fixed schema changed declared limits or allocated idle nodes")
			}
			fixed, err := schemaDecoderBackingBytes(test.schema, maximum, maximum)
			if err != nil {
				t.Fatal(err)
			}
			generic, err := DecoderBackingBytes(maximum, maximum)
			if err != nil || fixed >= generic {
				t.Fatal("fixed schema retained full-map normalization backing", fixed, generic, err)
			}
			for _, schema := range []string{"", "ClientHello"} {
				if _, err := d.DecodeShape([]byte{0xa0}, schema, DecodeContext{}); err != CBORFailure("configuration_capacity") {
					t.Fatal("fixed workspace accepted another grammar", schema, err)
				}
			}
			if _, err := d.DecodeRecordBody([]byte{0xa0}, FramePing, RecordHeader{}, ClientToServer, DecodeContext{}); err != CBORFailure("configuration_capacity") {
				t.Fatal("record entry point bypassed the fixed schema", err)
			}
			doc, err := d.DecodeMap(wire, test.schema, DecodeContext{})
			if err != nil {
				t.Fatal("maximum legal scalar was refused", err)
			}
			if text, _ := doc.Root().Named(test.schema, "tenant_id").Text(); len(text) != 128 || !bytes.Equal(doc.Bytes(), wire) {
				t.Fatal("fixed decoder changed complete canonical input")
			}
			if len(d.input) != len(wire) || d.used > len(d.nodes) || len(d.nodes) > min(maximum, len(wire)) {
				t.Fatal("fixed decoder retained nodes beyond its current input")
			}
			if _, err := d.DecodeMap(oracleBytes(t, seed.Hex), test.schema, DecodeContext{}); err != CBORFailure("decoder_busy") || !bytes.Equal(doc.Bytes(), wire) {
				t.Fatal("a second decode replaced a live document", err)
			}
			doc.Release()
			if d.input != nil || d.nodes != nil || d.used != 0 || d.size != 0 || d.active {
				t.Fatal("released fixed document retained its node arena")
			}
			// Reuse must restore the original declared capacity after a smaller map.
			// Views remain attached to one arena until each real Release.
			for _, input := range [][]byte{oracleBytes(t, seed.Hex), wire} {
				doc, err := d.DecodeMap(input, test.schema, DecodeContext{})
				if err != nil {
					t.Fatal("fixed decoder lost capacity during reuse", err)
				}
				if !bytes.Equal(doc.Bytes(), input) || len(d.input) != len(input) || d.used > len(d.nodes) || len(d.nodes) > min(maximum, len(input)) {
					t.Fatal("reused fixed decoder changed its current input or node arena")
				}
				doc.Release()
			}
			shortNodes, err := newSchemaDecoder(test.schema, maximum, 1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := shortNodes.DecodeMap(wire, test.schema, DecodeContext{}); err != CBORFailure("node_capacity") {
				t.Fatal("declared node rejection changed", err)
			}
			if shortNodes.input != nil || shortNodes.nodes != nil || shortNodes.active || shortNodes.used != 0 || shortNodes.size != 0 {
				t.Fatal("failed fixed decode retained its arena or live state")
			}
			shortBytes, err := newSchemaDecoder(test.schema, len(wire)-1, maximum)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := shortBytes.DecodeMap(wire, test.schema, DecodeContext{}); err != CBORFailure("map_size") {
				t.Fatal("declared byte rejection changed", err)
			}
			oracleField(t, r.cborReference, test.schema, root, "tenant_id").data = []byte(strings.Repeat("a", 129))
			if doc, err := d.DecodeMap(root.encode(nil), test.schema, DecodeContext{}); err == nil {
				doc.Release()
				t.Fatal("oversized schema text was accepted")
			}
			if d.input != nil || d.nodes != nil || d.active || d.used != 0 || d.size != 0 {
				t.Fatal("rejected schema text retained its arena or live state")
			}
			doc, err = d.DecodeMap(wire, test.schema, DecodeContext{})
			if err != nil {
				t.Fatal("a rejected decode reduced the original reusable limits", err)
			}
			doc.Release()
		})
	}
}

func TestRuntimeHelloFixedWorkspacesPreserveCompleteBuilderBinding(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	limits := HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}
	w, err := NewHelloWorkspace(limits)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		schema  string
		decoder *Decoder
		bytes   int
	}{{"ClientHello", w.client, limits.HelloBytes}, {"ServerHello", w.server, limits.HelloBytes}, {"TransportContext", w.context, limits.ContextBytes}} {
		if test.decoder.byteLimit != test.bytes || test.decoder.input != nil || test.decoder.nodeLimit != limits.HelloNodes || test.decoder.nodes != nil {
			t.Fatal("Hello fixed workspace changed complete limits or allocated idle nodes", test.schema)
		}
		if _, err := test.decoder.DecodeShape([]byte{0xa0}, "FreshnessHead", DecodeContext{}); err != CBORFailure("configuration_capacity") {
			t.Fatal("Hello workspace accepted a foreign schema", test.schema, err)
		}
	}
	client, err := w.BuildClientHello(make([]byte, limits.HelloBytes), f.artifact, 5, f.binding.attempt, 3, 2, []byte("client hint"))
	if err != nil {
		t.Fatal(err)
	}
	policy := HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1}
	server, built, err := w.BuildServerHello(make([]byte, limits.HelloBytes), f.artifact, 5, f.binding.attempt, client, 3, policy, []byte("server hint"))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := w.Bind(f.artifact, 5, f.binding.attempt, client, server, policy)
	if err != nil || bound.transcript != built.transcript || bound.transport != built.transport {
		t.Fatal("fixed workspaces changed the original Hello binding", err)
	}
	for _, decoder := range []*Decoder{w.client, w.server, w.context} {
		if decoder.input != nil || decoder.nodes != nil || decoder.active {
			t.Fatal("Hello builder or binding retained its completed decoder arena")
		}
	}
}

func TestRuntimePrivateDecoderCompactsOnlyWithinOriginalNodeAllowance(t *testing.T) {
	seed := oracleSeed(t, "freshness_head_fields")
	wire := oracleBytes(t, seed.Hex)
	generic, err := NewDecoder(len(wire)+64, len(wire))
	if err != nil {
		t.Fatal(err)
	}
	original, err := generic.DecodeMap(wire, "FreshnessHead", DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer original.Release()
	used := generic.used
	if used >= len(wire)-1 {
		t.Fatal("fixture does not distinguish encoded bytes from used nodes")
	}
	for _, test := range []struct {
		name            string
		nodes, retained int
	}{
		{"exact_replacement_overlap", len(wire) + used, used},
		{"no_replacement_overlap", used + 1, used + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, err := newSchemaDecoder("FreshnessHead", len(wire)+64, test.nodes)
			if err != nil {
				t.Fatal(err)
			}
			if d.input != nil || d.nodes != nil || d.byteLimit != len(wire)+64 || d.nodeLimit != test.nodes {
				t.Fatal("private constructor allocated idle arrays or lost original limits")
			}
			doc, err := d.DecodeMap(wire, "FreshnessHead", DecodeContext{})
			if err != nil || d.used != used || len(d.nodes) != test.retained || len(d.input) != len(wire) || !bytes.Equal(doc.Bytes(), wire) {
				t.Fatal("private backing changed canonical bytes, used nodes or prepaid overlap", err)
			}
			view := doc.Root().Named("FreshnessHead", "state_digest")
			borrowed, ok := view.ByteString()
			if !ok {
				t.Fatal("complete original State digest view is missing")
			}
			input, nodes := d.input, d.nodes
			doc.Release()
			if d.input != nil || d.nodes != nil || view.valid() || !bytes.Equal(input, make([]byte, len(input))) || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("private Release retained input arrays or valid original views")
			}
			for _, node := range nodes {
				if node != (cborNode{}) {
					t.Fatal("private Release retained original node evidence")
				}
			}
			// Exhausted document generations must retire the newly allocated input
			// and nodes after parsing, under the same declared reusable capacities.
			d.generation = ^uint64(0)
			if doc, err := d.DecodeMap(wire, "FreshnessHead", DecodeContext{}); doc != nil || err != CBORFailure("decoder_retired") {
				t.Fatal("retired private decoder admitted another document", err)
			}
			if d.input != nil || d.nodes != nil || d.active || d.used != 0 || d.size != 0 || d.byteLimit != len(wire)+64 || d.nodeLimit != test.nodes {
				t.Fatal("retired private decoder retained backing or changed original limits")
			}
		})
	}
	if len(generic.input) != len(wire)+64 || len(generic.nodes) != len(wire) {
		t.Fatal("private compaction changed generic reusable decoder backing")
	}
}
