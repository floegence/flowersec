package protocolv4

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestBootstrapPrefixMatchesGeneratedContract(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []struct{ ID, Hex string } }
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	spec, enabled, err := Bootstrap("services")
	if err != nil || !enabled {
		t.Fatal(spec, enabled, err)
	}
	found := 0
	for _, v := range corpus.Vectors {
		var epoch uint32
		switch v.ID {
		case "bootstrap_open_epoch0":
		case "bootstrap_open_max_epoch":
			epoch = ^uint32(0)
		default:
			continue
		}
		wire, _, err := EncodeOpen(make([]byte, 256), RecordHeader{Scope: spec.Scope, Epoch: epoch}, spec.Opener, spec.Kind, nil, spec.ReceiveLimit)
		if err != nil || hex.EncodeToString(wire) != v.Hex {
			t.Fatal(v.ID, hex.EncodeToString(wire), err)
		}
		found++
	}
	if found != 2 {
		t.Fatal("missing bootstrap fixtures", found)
	}
	if _, enabled, err = Bootstrap("transport"); err != nil || enabled {
		t.Fatal(enabled, err)
	}
	if _, _, err = Bootstrap("unknown"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}
