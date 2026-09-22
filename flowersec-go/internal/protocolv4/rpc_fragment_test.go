package protocolv4

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

type rpcFragmentVector struct {
	ID, Hex       string
	ExpectedError string `json:"expected_error"`
}

func rpcFragmentVectors(t testing.TB) []rpcFragmentVector {
	t.Helper()
	wire, err := os.ReadFile("../../../testdata/transport_v4/fragments.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SHA     string `json:"schema_sha256"`
		Vectors []rpcFragmentVector
	}
	if err := json.Unmarshal(wire, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SHA != SchemaSHA256 {
		t.Fatal("fragment corpus binding drift")
	}
	return corpus.Vectors
}

// v4.go_rpc_codecs.fragments
func TestRPCFragmentSharedCorpus(t *testing.T) {
	for _, v := range rpcFragmentVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			wire := domainHex(t, v.Hex)
			f, err := DecodeRPCFragment(wire)
			if v.ExpectedError != "" {
				if err != CBORFailure("fragment_"+v.ExpectedError) {
					t.Fatal(v.ExpectedError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			out := make([]byte, len(wire))
			n, err := EncodeRPCFragment(out, f)
			if err != nil || n != len(wire) || !bytes.Equal(wire, out) {
				t.Fatal("shared vector roundtrip", err)
			}
			// Both borrowed views clamp capacity to prevent access to adjacent
			// plaintext in the caller's original read allocation.
			if cap(f.Header) != len(f.Header) || cap(f.Payload) != len(f.Payload) {
				t.Fatal("unbounded borrowed view")
			}
		})
	}
}

func parseRPCChunks(t testing.TB, wire []byte, step int) ([]RPCFragment, error) {
	t.Helper()
	p, err := NewRPCFragmentParser()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var result []RPCFragment
	for at := 0; at < len(wire); {
		end := min(len(wire), at+step)
		for at < end {
			n, part, err := p.Next(wire[at:end])
			if err != nil {
				return result, err
			}
			if n == 0 {
				t.Fatal("parser made no progress with nonempty input")
			}
			at += n
			if part.Fragment.Serial == 0 {
				continue
			}
			f := part.Fragment
			if cap(f.Header) != len(f.Header) || cap(f.Payload) != len(f.Payload) {
				t.Fatal("unbounded part view")
			}
			if part.First {
				if part.ChunkOffset != 0 {
					t.Fatal("first chunk offset")
				}
				f.Header, f.Payload = bytes.Clone(f.Header), bytes.Clone(f.Payload)
				result = append(result, f)
			} else {
				last := &result[len(result)-1]
				if f.Kind != RPCData || last.Serial != f.Serial || last.Offset != f.Offset || int(part.ChunkOffset) != len(last.Payload) {
					t.Fatal("partial DATA binding")
				}
				last.Payload = append(last.Payload, f.Payload...)
			}
		}
	}
	return result, p.End()
}

func TestRPCFragmentParserArbitraryReadBoundaries(t *testing.T) {
	var wire []byte
	var expected []RPCFragment
	for _, v := range rpcFragmentVectors(t) {
		if v.ExpectedError != "" {
			continue
		}
		b := domainHex(t, v.Hex)
		f, err := DecodeRPCFragment(b)
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, f)
		wire = append(wire, b...)
	}
	for _, n := range []int{1, 2, 4, 5, 12, 13, 16, 17, 18, 21, 22, 23, 24, 511, 512, 534, 535, 4096, 16384, len(wire)} {
		result, err := parseRPCChunks(t, wire, n)
		if err != nil || !reflect.DeepEqual(result, expected) {
			t.Fatal("split", n, err)
		}
	}
}

func TestRPCFragmentParserRejectsTruncationAndSeals(t *testing.T) {
	for _, v := range rpcFragmentVectors(t) {
		wire := domainHex(t, v.Hex)
		if v.ExpectedError == "" {
			for _, end := range []int{1, 4, 5, 12, len(wire) - 1} {
				if end >= len(wire) {
					continue
				}
				if _, err := parseRPCChunks(t, wire[:end], 3); err == nil {
					t.Fatal("truncated fragment accepted", v.ID, end)
				}
			}
		} else if _, err := parseRPCChunks(t, wire, 1); err == nil {
			t.Fatal("malformed fragment accepted", v.ID)
		}
	}
	p, _ := NewRPCFragmentParser()
	_, _, err := p.Next([]byte{0xff, 0xff, 0xff, 0xff, 1})
	if err == nil {
		t.Fatal("unbounded body accepted")
	}
	if _, _, next := p.Next(make([]byte, 32)); next != err {
		t.Fatal("parser recovered after framing error")
	}
	p.Close()
	if err := p.End(); err != CBORFailure("fragment_closed") {
		t.Fatal(err)
	}
}

func TestRPCFragmentEncodingAliasAndLocalRefusal(t *testing.T) {
	var fixed [13]byte
	if _, err := EncodeRPCFragment(fixed[:], RPCFragment{Kind: RPCStopOutput}); err != CBORFailure("fragment_request_serial_range") {
		t.Fatal("STOP_OUTPUT serial projection", err)
	}
	if fixed != ([13]byte{}) {
		t.Fatal("invalid STOP_OUTPUT changed output")
	}
	for _, kind := range []RPCFragmentKind{RPCBegin, RPCData} {
		buffer := []byte(strings.Repeat("x", 600))
		saved := bytes.Clone(buffer[:64])
		f := RPCFragment{Kind: kind, Serial: 1}
		if kind == RPCBegin {
			f.Header = buffer[:64]
		} else {
			f.Payload = buffer[:64]
		}
		n, err := EncodeRPCFragment(buffer, f)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeRPCFragment(buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(saved, append(decoded.Header, decoded.Payload...)) {
			t.Fatal("aliased input corrupted")
		}
		before := bytes.Clone(buffer)
		if _, err := EncodeRPCFragment(buffer[:1], f); err == nil {
			t.Fatal("short output accepted")
		}
		if !bytes.Equal(buffer, before) {
			t.Fatal("local refusal changed output")
		}
	}
}

func TestRPCFragmentParserNoPayloadAllocation(t *testing.T) {
	p, _ := NewRPCFragmentParser()
	wire := make([]byte, 16384)
	n, err := EncodeRPCFragment(wire, RPCFragment{Kind: RPCData, Serial: 1, Payload: wire[17:]})
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		used, part, err := p.Next(wire[:n])
		if err != nil || used != n || !part.Last || !part.First || len(part.Fragment.Payload) != n-17 {
			panic("invalid DATA")
		}
	})
	if allocs != 0 {
		t.Fatal("payload parser allocated", allocs)
	}
}

func FuzzRPCFragmentParser(f *testing.F) {
	for _, v := range rpcFragmentVectors(f) {
		f.Add(domainHex(f, v.Hex), uint8(7))
	}
	f.Fuzz(func(t *testing.T, wire []byte, step uint8) {
		if len(wire) > 65536 {
			t.Skip()
		}
		parts, err := parseRPCChunks(t, wire, int(step)+1)
		if expected, wholeErr := DecodeRPCFragment(wire); wholeErr == nil {
			if err != nil || len(parts) != 1 || !reflect.DeepEqual(parts[0], expected) {
				t.Fatal("incremental parser disagrees with complete fragment", err)
			}
		}
	})
}
