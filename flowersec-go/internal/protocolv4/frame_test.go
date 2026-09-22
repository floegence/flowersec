package protocolv4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRuntimeFrameVariants(t *testing.T) {
	d, err := NewDecoder(32768, 5000)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, v := range cborRefVectors(t) {
		if v.ExpectedError != "" || !recordSchema(v.Schema) || v.Schema == "OPEN_STREAM" || v.Schema == "terminal_tuple" || v.Schema == "RekeyBarrierEntry" {
			continue
		}
		input, _ := hex.DecodeString(v.Hex)
		c := shapeContext(v.Limits)
		context := DecodeContext{Limits: c.limits, Selectors: c.selectors}
		shape, err := d.DecodeShape(input, v.Schema, context)
		if err != nil {
			t.Fatal(v.ID, err)
		}
		header := RecordHeader{}
		direction := ClientToServer
		var frame FrameType
		switch v.Schema {
		case "STREAM_DATA":
			frame = FrameStreamData
			header.Scope, _ = shape.Root().Named(v.Schema, "stream_id").Uint()
			n, _ := shape.Root().Named(v.Schema, "direction").Uint()
			direction = Direction(n)
		case "DATAGRAM":
			frame = FrameDatagram
			header.Scope = DatagramScope()
		case "ERROR":
			frame = FrameError
		case "CLOSE":
			frame = FrameClose
		case "GOAWAY":
			frame = FrameGoAway
		case "PING":
			frame = FramePing
		case "PONG":
			frame = FramePong
		default:
			frame = FrameStreamAck
			if len(v.Schema) >= 6 && v.Schema[:6] == "REKEY_" {
				frame = FrameRekey
				direction = Direction(*d.registry.Maps[v.Schema].SenderRole)
			}
		}
		if frame == FrameStreamData || frame == FrameDatagram {
			n, _ := shape.Root().Named(v.Schema, "epoch").Uint()
			header.Epoch = uint32(n)
			header.Sequence, _ = shape.Root().Named(v.Schema, "sequence").Uint()
		}
		shape.Release()
		t.Run(v.ID, func(t *testing.T) {
			f, err := d.DecodeRecordBody(input, frame, header, direction, context)
			if err != nil {
				t.Fatal(err)
			}
			if f.Schema != v.Schema || !bytes.Equal(f.Document.Bytes(), input) {
				t.Fatal("variant changed")
			}
			f.Release()
		})
		count++
	}
	if count < 20 {
		t.Fatalf("incomplete record variants: %d", count)
	}
}

func TestRuntimeOpenDigestAndBinding(t *testing.T) {
	d, err := NewDecoder(8192, 128)
	if err != nil {
		t.Fatal(err)
	}
	var dst [8192]byte
	var digest [32]byte
	fields := []Field{{Name: "stream_id", Number: 3}, {Name: "direction", Number: 0}, {Name: "scope", Number: 3}, {Name: "epoch", Number: 0}, {Name: "sequence", Number: 0}, {Name: "kind", Kind: TextString, Text: "test/raw"}, {Name: "metadata", Kind: ByteString}, {Name: "initial_receive_limit", Number: 128}, {Name: "open_digest", Kind: ByteString, Bytes: digest[:]}}
	input, err := EncodeMap(dst[:], "OPEN_STREAM", fields)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := d.DecodeShape(input, "OPEN_STREAM", DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	f := &Frame{Document: doc, Schema: "OPEN_STREAM"}
	digest, err = f.OpenDigest()
	if err != nil {
		t.Fatal(err)
	}
	doc.Release()
	input, err = EncodeMap(dst[:], "OPEN_STREAM", fields)
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.DecodeRecordBody(input, FrameOpenStream, RecordHeader{Scope: 3}, ClientToServer, DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	got.Release()
	input[len(input)-1] ^= 1
	if _, err = d.DecodeRecordBody(input, FrameOpenStream, RecordHeader{Scope: 3}, ClientToServer, DecodeContext{}); err != CBORFailure("open_digest") {
		t.Fatal(err)
	}
}
