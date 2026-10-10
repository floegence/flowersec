package protocolv4

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestOnceDocumentRetainsOriginalRouteViewsAndBindings(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	wire, _, err := f.artifact.CopyCandidateRoute(5, make([]byte, 16384))
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(wire)
	generic, err := NewDecoder(16384, 1024)
	if err != nil {
		t.Fatal(err)
	}
	before, err := generic.DecodeMap(wire, "Route", DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer before.Release()
	carrier, ok := before.Root().Named("Route", "direct_leg").Named("Leg", "carrier").Uint()
	if !ok {
		t.Fatal("original direct route has no carrier")
	}
	wantLeg, wantBinding, err := before.BindCarrierRoute(ClientToServer, false, false, carrier, RelayDeploymentBinding{})
	if err != nil {
		t.Fatal(err)
	}
	wantEncodedLeg := bytes.Clone(wantLeg.Encoded())
	doc, err := NewOnceDocument(wire, "Route", 16384, 1024, DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	clear(wire)
	before.Release()
	if !bytes.Equal(doc.Bytes(), original) || !bytes.Equal(doc.Root().Encoded(), original) {
		t.Fatal("retained route aliases caller or another decoder's storage")
	}
	leg, binding, err := doc.BindCarrierRoute(ClientToServer, false, false, carrier, RelayDeploymentBinding{})
	if err != nil || binding != wantBinding || !bytes.Equal(leg.Encoded(), wantEncodedLeg) {
		t.Fatal("once document changed original carrier binding", err)
	}
	if err := doc.MatchCandidateRoute(f.binding.Winner()); err != nil {
		t.Fatal("once document changed the original candidate route", err)
	}
	wrong := f.binding.Winner()
	wrong.RouteDigest[0] ^= 1
	if err := doc.MatchCandidateRoute(wrong); err != CBORFailure("carrier_binding_invalid") {
		t.Fatal("once document accepted a replacement route", err)
	}
	if err := doc.ValidateRules(DecodeContext{}); err != nil {
		t.Fatal("compaction lost the original route rule workspace", err)
	}
	view := doc.Root().Named("Route", "candidate_id")
	borrowed, ok := view.ByteString()
	if !ok || len(borrowed) != 16 {
		t.Fatal("retained candidate view is invalid")
	}
	doc.Release()
	if _, ok := view.ByteString(); ok || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("Release retained a live view or uncleared original route bytes")
	}
}

func TestOnceDocumentPreservesOriginalDecodeRejections(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	wire, err := f.fsb.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	nodes := f.fsb.document.decoder.used
	certificate := f.fsb.Field("client_certificate")
	if nodes > len(wire) || !certificate.valid() || f.fsb.document.decoder.nodes[certificate.index].embedded < 0 {
		t.Fatal("fixture does not cover the encoded-schema node bound")
	}
	for _, test := range []struct {
		name, schema string
		wire         []byte
		bytes, nodes int
	}{
		{"exact_embedded_nodes", "FSB4", wire, len(wire), nodes},
		{"node_limit", "FSB4", wire, len(wire), nodes - 1},
		{"byte_limit", "FSB4", wire, len(wire) - 1, nodes},
		{"truncated", "FSB4", wire[:len(wire)-1], len(wire), nodes},
		{"trailing", "FSB4", append(bytes.Clone(wire), 0), len(wire) + 1, nodes + 1},
		{"unknown_schema", "UnknownOnceDocument", wire, len(wire), nodes},
		{"empty_input", "FSB4", nil, len(wire), nodes},
		{"invalid_bytes", "FSB4", wire, 0, nodes},
		{"invalid_nodes", "FSB4", wire, len(wire), 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			generic, want := NewDecoder(test.bytes, test.nodes)
			var original *Document
			if want == nil {
				original, want = generic.DecodeMap(test.wire, test.schema, f.context)
			}
			if original != nil {
				defer original.Release()
			}
			doc, got := NewOnceDocument(test.wire, test.schema, test.bytes, test.nodes, f.context)
			if got != want {
				t.Fatal("once construction changed an original decode refusal", got, want)
			}
			if doc != nil {
				defer doc.Release()
				if !bytes.Equal(doc.Bytes(), test.wire) || doc.decoder.used != generic.used || doc.decoder.used > len(test.wire) {
					t.Fatal("encoded schemas changed node identity or escaped the wire bound")
				}
			}
		})
	}
}

func TestOnceDocumentRejectsEmbeddedTrailingBytesAndInvalidRules(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	for _, test := range []struct{ name, schema string }{
		{"embedded_trailing_bytes", "FSB4"},
		{"credential_time_relation", "IdentityCertificate"},
		{"oversized_text", "IdentityCertificate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			schema := test.schema
			original := f.fsb
			if schema == "IdentityCertificate" {
				original = f.certificate
			}
			wire, err := original.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			root, _, err := f.r.decode(wire, schema, nil, 65536)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "embedded_trailing_bytes" {
				certificate := oracleField(t, f.r.cborReference, schema, root, "client_certificate")
				certificate.data = append(bytes.Clone(certificate.data), 0)
			} else if test.name == "oversized_text" {
				oracleField(t, f.r.cborReference, schema, root, "subject_id").data = []byte(strings.Repeat("a", 129))
			} else {
				expiry := oracleField(t, f.r.cborReference, schema, root, "expires_at_ms")
				expiry.n = oracleField(t, f.r.cborReference, schema, root, "issued_at_ms").n
			}
			invalid := root.encode(nil)
			generic, err := NewDecoder(65536, 4096)
			if err != nil {
				t.Fatal(err)
			}
			if accepted, want := generic.DecodeMap(invalid, schema, f.context); want == nil {
				accepted.Release()
				t.Fatal("negative original fixture was accepted")
			} else if accepted, got := NewOnceDocument(invalid, schema, 65536, 4096, f.context); got != want || accepted != nil {
				if accepted != nil {
					accepted.Release()
				}
				t.Fatal("once document weakened embedded shape or stateless rules", got, want)
			}
		})
	}
}

func TestOnceDocumentKeepsOriginalBackingReservedUntilOwnerCleanup(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	wire, _, err := f.artifact.CopyCandidateRoute(5, make([]byte, 16384))
	if err != nil {
		t.Fatal(err)
	}
	charge, err := DecoderBackingBytes(16384, 1024)
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 1, ReservationSlots: 4, ReferenceSlots: 8}
	rootBytes, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit = resourcev4.Vector{resourcev4.SDKBytes: rootBytes + charge}
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Kind: 1, Instance: [16]byte{1}, Backing: [16]byte{1}, Direction: 1}
	reserved, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: charge})
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.Release()
	before := root.Snapshot()
	doc, err := NewOnceDocument(wire, "Route", 16384, 1024, DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	if root.Snapshot() != before || len(doc.decoder.input) != len(wire) || len(doc.decoder.nodes) >= 1024 {
		t.Fatal("private compaction changed the original charge or retained maximum arrays")
	}
	owner.Instance, owner.Backing = [16]byte{2}, [16]byte{2}
	if extra, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 1}); !errors.Is(err, resourcev4.ErrCapacity) {
		extra.Release()
		t.Fatal("compaction refunded the original owner's reserved backing", err)
	}
	doc.Release()
	if root.Snapshot() != before {
		t.Fatal("document release prematurely retired the caller's original reservation")
	}
	reserved.Release()
	root.Close()
	if after := root.Snapshot(); !after.CleanupComplete || after.Reservations != 0 || after.References != 0 || after.Charged != (resourcev4.Vector{resourcev4.SDKBytes: rootBytes}) {
		t.Fatal("original reservation did not retire at actual owner cleanup", after)
	}
}
