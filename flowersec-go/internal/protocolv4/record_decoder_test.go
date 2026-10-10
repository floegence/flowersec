package protocolv4

import (
	"bytes"
	"maps"
	"testing"
)

func TestRuntimeRecordDecoderBinaryCapacity(t *testing.T) {
	const maximum = 1 << 20
	recordBytes, err := RecordDecoderBackingBytes(maximum, 64)
	if err != nil {
		t.Fatal(err)
	}
	genericBytes, err := DecoderBackingBytes(maximum, 64)
	if err != nil {
		t.Fatal(err)
	}
	if recordBytes > 2*maximum || genericBytes < 16*recordBytes {
		t.Fatal("binary frame retained payload-sized NFC workspaces", recordBytes, genericBytes)
	}
	d, err := NewRecordDecoder(maximum, 64)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0xff}, maximum-128)
	encoded, err := EncodeMap(make([]byte, maximum), "STREAM_DATA", []Field{
		{Name: "stream_id", Number: 1}, {Name: "direction", Number: 0}, {Name: "epoch", Number: 0},
		{Name: "sequence", Number: 0}, {Name: "offset", Number: 0}, {Name: "fin", Kind: Boolean}, {Name: "data", Kind: ByteString, Bytes: data},
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := d.DecodeRecordBody(encoded, FrameStreamData, RecordHeader{Scope: 1}, ClientToServer, DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": uint64(len(data))}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := f.Field("data").ByteString()
	if !ok || !bytes.Equal(got, data) {
		t.Fatal("binary capacity shrunk")
	}
	f.Release()
}

func TestRecordDecoderKeepsFullChargeAndOwnsOnlyActualInput(t *testing.T) {
	const maximum, nodes = 4096, 128
	charge, err := RecordDecoderBackingBytes(maximum, nodes)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewRecordDecoder(maximum, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if d.input != nil || d.nodes != nil || d.byteLimit != maximum || d.nodeLimit != nodes || d.fixedSchema != "" || d.borrowed {
		t.Fatal("idle record decoder lost its original independent capacities")
	}
	for _, size := range []int{maximum - 128, 1, maximum - 128} {
		payload := bytes.Repeat([]byte{0xff}, size)
		wire, err := EncodeMap(make([]byte, maximum), "STREAM_DATA", []Field{
			{Name: "stream_id", Number: 1}, {Name: "direction", Number: 0}, {Name: "epoch", Number: 0},
			{Name: "sequence", Number: 0}, {Name: "offset", Number: 0}, {Name: "fin", Kind: Boolean}, {Name: "data", Kind: ByteString, Bytes: payload},
		})
		if err != nil {
			t.Fatal(err)
		}
		frame, err := d.DecodeRecordBody(wire, FrameStreamData, RecordHeader{Scope: 1}, ClientToServer, DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": maximum}})
		if err != nil {
			t.Fatal(err)
		}
		got, ok := frame.Field("data").ByteString()
		if !ok || !bytes.Equal(got, payload) || len(d.input) != len(wire) || cap(d.input) != len(wire) || len(d.nodes) > min(nodes, len(wire)) {
			t.Fatal("record backing did not follow actual input within original bounds")
		}
		if _, err := d.DecodeRecordBody(wire, FrameStreamData, RecordHeader{Scope: 1}, ClientToServer, DecodeContext{}); err != CBORFailure("decoder_busy") {
			t.Fatal("held frame admitted another input", err)
		}
		clear(wire)
		if !bytes.Equal(got, payload) {
			t.Fatal("record plaintext aliased its original caller")
		}
		input, arena := d.input, d.nodes
		frame.Release()
		if d.input != nil || d.nodes != nil || !bytes.Equal(input, make([]byte, len(input))) || !bytes.Equal(got, make([]byte, len(got))) {
			t.Fatal("Release retained original private input")
		}
		for _, node := range arena {
			if node != (cborNode{}) {
				t.Fatal("Release retained original private node")
			}
		}
		if current, err := RecordDecoderBackingBytes(maximum, nodes); err != nil || current != charge {
			t.Fatal("actual backing reduced original admission charge", current, charge, err)
		}
	}
}

func TestRecordDecoderOriginalRefusalsClearAndAllowRetry(t *testing.T) {
	d, err := NewRecordDecoder(64, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		wire []byte
		err  error
	}{{make([]byte, 65), CBORFailure("map_size")}, {[]byte{0xa1, 0, 0}, CBORFailure("node_capacity")}, {[]byte{0xa1}, CBORFailure("truncated")}} {
		if _, err := d.DecodeShape(test.wire, "", DecodeContext{}); err != test.err || d.input != nil || d.nodes != nil || d.active {
			t.Fatal("original rejection retained private input or changed its error", err, test.err)
		}
		doc, err := d.DecodeShape([]byte{0xa0}, "", DecodeContext{})
		if err != nil {
			t.Fatal("original refusal prevented legal retry", err)
		}
		doc.Release()
	}
	generic, err := NewDecoder(64, 2)
	if err != nil || len(generic.input) != 64 || len(generic.nodes) != 2 || generic.byteLimit != 0 || generic.nodeLimit != 0 {
		t.Fatal("generic decoder lost fixed original backing", err)
	}
}

func TestRecordDecoderCompleteShapePrecedesPrivateNodeCompaction(t *testing.T) {
	d, err := NewRecordDecoder(256, 128)
	if err != nil {
		t.Fatal(err)
	}
	// Isolate a synthetic encoded nested field from the shared generated
	// registry. Final record shape must retain room to parse its original bytes.
	registry := *d.registry
	registry.Maps = maps.Clone(registry.Maps)
	shape := *registry.Maps["STREAM_DATA"]
	shape.Fields, shape.byID, shape.byName = maps.Clone(shape.Fields), maps.Clone(shape.byID), maps.Clone(shape.byName)
	data := *shape.byName["data"]
	data.EncodedSchemaRef = "test_record_embedded"
	shape.byID[data.id], shape.byName[data.Name] = &data, &data
	for id, field := range shape.Fields {
		if field.Name == "data" {
			shape.Fields[id] = &data
		}
	}
	nested := &wireField{Name: "n", Type: "uint64", id: 0, width: 64}
	registry.Maps["test_record_embedded"] = &wireMap{Fields: map[string]*wireField{"0": nested}, Required: []uint64{0}, byID: map[uint64]*wireField{0: nested}, byName: map[string]*wireField{"n": nested}}
	registry.Maps["STREAM_DATA"] = &shape
	d.registry = &registry
	wire, err := EncodeMap(make([]byte, 256), "STREAM_DATA", []Field{
		{Name: "stream_id", Number: 1}, {Name: "direction", Number: 0}, {Name: "epoch", Number: 0},
		{Name: "sequence", Number: 0}, {Name: "offset", Number: 0}, {Name: "fin", Kind: Boolean}, {Name: "data", Kind: ByteString, Bytes: []byte{0xa1, 0, 7}},
	})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := d.DecodeRecordBody(wire, FrameStreamData, RecordHeader{Scope: 1}, ClientToServer, DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 128}})
	if err != nil {
		t.Fatal("record compaction starved final nested grammar", err)
	}
	defer frame.Release()
	if d.used != 18 || len(d.nodes) < d.used {
		t.Fatal("complete selected shape did not retain embedded nodes", d.used, len(d.nodes))
	}
}

func TestRuntimeEncodeOpenOriginalDigest(t *testing.T) {
	d, err := NewRecordDecoder(8192, 64)
	if err != nil {
		t.Fatal(err)
	}
	header := RecordHeader{Scope: 4, Epoch: 32768}
	wire, digest, err := EncodeOpen(make([]byte, 8192), header, ServerToClient, "example/\u00e9", bytes.Repeat([]byte{0xff}, 4096), ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	f, err := d.DecodeRecordBody(wire, FrameOpenStream, header, ServerToClient, DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.OpenDigest()
	if err != nil || got != digest {
		t.Fatal(got, digest, err)
	}
	f.Release()
	wire, _, err = EncodeOpen(make([]byte, 1024), RecordHeader{Scope: 1}, ClientToServer, string(bytes.Repeat([]byte{'x'}, 129)), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.DecodeRecordBody(wire, FrameOpenStream, RecordHeader{Scope: 1}, ClientToServer, DecodeContext{}); err != CBORFailure("text_capacity") {
		t.Fatal("oversized text admitted", err)
	}
}
