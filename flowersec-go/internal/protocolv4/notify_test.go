package protocolv4

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func notifyVectors(t testing.TB) []rpcFragmentVector {
	t.Helper()
	wire, err := os.ReadFile("../../../testdata/transport_v4/notify.json")
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
		t.Fatal("notification corpus binding drift")
	}
	return corpus.Vectors
}

// v4.go_notify.framing
func TestNotifySharedCorpus(t *testing.T) {
	c, err := NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range notifyVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			wire := domainHex(t, v.Hex)
			h, body, err := c.DecodeNotify(wire)
			if v.ExpectedError != "" {
				if err != CBORFailure(v.ExpectedError) {
					t.Fatal(v.ExpectedError, err)
				}
				return
			}
			if err != nil || !h.Notify() || cap(body) != len(body) {
				t.Fatal(h.Kind(), err)
			}
			prefix := wire[2 : len(wire)-len(body)]
			out := bytes.Clone(wire)
			n, err := c.EncodeNotifyPrefix(out, out[2:len(out)-len(body)])
			if err != nil || n != len(prefix)+2 || !bytes.Equal(out, wire) {
				t.Fatal("overlap prefix", err)
			}
			for step := 1; step <= len(wire); step++ {
				p, err := NewNotifyParser()
				if err != nil {
					t.Fatal(err)
				}
				// Identical physical messages each have their own full boundary.
				all := bytes.Repeat(wire, 2)
				var first, last int
				var payload []byte
				for at := 0; at < len(all); {
					end := min(at+step, len(all))
					for at < end {
						n, part, err := p.Next(all[at:end])
						if err != nil || n == 0 {
							t.Fatal("incremental progress", step, at, err)
						}
						at += n
						if part.First {
							first++
						}
						if part.Last {
							last++
						}
						if cap(part.Payload) != len(part.Payload) {
							t.Fatal("borrow capacity")
						}
						payload = append(payload, part.Payload...)
					}
				}
				if err := p.End(); err != nil || first != 2 || last != 2 || !bytes.Equal(payload, bytes.Repeat(body, 2)) {
					t.Fatal("physical boundaries", first, last, err)
				}
				p.Close()
			}
		})
	}
}

func TestNotifyTruncatedAndTerminalParser(t *testing.T) {
	var wire []byte
	for _, v := range notifyVectors(t) {
		if v.ID == "observation_notify_payload" {
			wire = domainHex(t, v.Hex)
		}
	}
	for cut := 1; cut < len(wire); cut++ {
		p, _ := NewNotifyParser()
		for at := 0; at < cut; {
			n, _, err := p.Next(wire[at:cut])
			if err != nil || n == 0 {
				t.Fatal(cut, err)
			}
			at += n
		}
		if err := p.End(); err != CBORFailure("notify_truncated") {
			t.Fatal(cut, err)
		}
		if _, _, err := p.Next(wire); err != CBORFailure("notify_truncated") {
			t.Fatal("terminal failure revived", err)
		}
	}
}
