package protocolv4

import (
	"bytes"
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
