package cryptov4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestCryptoInputSharedDomainBytes(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/domains.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Schema  string `json:"schema_sha256"`
		Vectors []struct {
			ID, Domain string
			Inputs     map[string]json.RawMessage
			Result     *struct {
				Input string `json:"input_hex"`
			}
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil || corpus.Schema != protocolv4.SchemaSHA256 {
		t.Fatal("stale domain corpus", err)
	}
	checked := 0
	for _, fixture := range corpus.Vectors {
		if fixture.Result == nil {
			continue
		}
		switch fixture.Domain {
		case "noise_prologue", "fsb_digest", "fsa_digest", "initial_root", "ready_identity", "ready_mac", "ready_key",
			"rekey_secret", "rekey_confirm_key", "rekey_init_digest", "rekey_transcript", "rekey_extract", "rekey_root":
			// MAC projection is exercised by TestRekeyProductionSharedCorpus.
			// This helper receives already-projected bytes, not a signed map.
		default:
			continue
		}
		checked++
		t.Run(fixture.ID, func(t *testing.T) {
			values, numbers := map[string][]byte{}, map[string]uint64{}
			for name, raw := range fixture.Inputs {
				switch raw[0] {
				case '{':
					var value struct {
						Bytes string `json:"$bytes"`
					}
					if err := json.Unmarshal(raw, &value); err != nil {
						t.Fatal(err)
					}
					values[name], err = hex.DecodeString(value.Bytes)
					if err != nil {
						t.Fatal(err)
					}
				case '"':
					var value string
					if err := json.Unmarshal(raw, &value); err != nil {
						t.Fatal(err)
					}
					values[name] = []byte(value)
				default:
					var value uint64
					if err := json.Unmarshal(raw, &value); err != nil {
						t.Fatal(err)
					}
					numbers[name] = value
				}
			}
			expected, err := hex.DecodeString(fixture.Result.Input)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := cryptoInput(fixture.Domain, values, numbers)
			if err != nil || !bytes.Equal(actual, expected) || len(actual) != cap(actual) {
				t.Fatal("domain bytes or exact backing changed", err, len(actual), cap(actual))
			}
			clear(actual)
			again, err := cryptoInput(fixture.Domain, values, numbers)
			if err != nil || !bytes.Equal(again, expected) {
				t.Fatal("output aliased immutable label/input", err)
			}
		})
	}
	if checked < 20 {
		t.Fatal("missing production domain fixture coverage", checked)
	}
}

func TestCryptoInputMaximumTranscriptUsesOneExactAllocation(t *testing.T) {
	if _, err := handshakeWire(); err != nil {
		t.Fatal(err)
	}
	// Isolate byte assembly at the full frame capacity. These opaque views are
	// not a claim that these repeated bytes pass the separate CBOR decoder.
	init := bytes.Repeat([]byte{0xa0}, protocolv4.MaxPayloadLength)
	reply := bytes.Repeat([]byte{0xa1}, protocolv4.MaxPayloadLength)
	values := map[string][]byte{"handshake_hash": make([]byte, 32), "profile": []byte(protocolv4.DHProfileX25519), "init": init, "reply": reply}
	numbers := map[string]uint64{"epoch": math.MaxUint32}
	allocations := testing.AllocsPerRun(5, func() {
		input, err := cryptoInput("rekey_transcript", values, numbers)
		if err != nil || len(input) != 127+len(init)+len(reply) || cap(input) != len(input) {
			t.Fatal("full transcript backing is not exact", err, len(input), cap(input))
		}
		if !bytes.Equal(input[len(input)-len(reply):], reply) {
			t.Fatal("transcript lost the original reply")
		}
		clear(input)
	})
	if allocations != 1 {
		t.Fatal("domain assembly allocated intermediate payload copies", allocations)
	}
	if init[0] != 0xa0 || reply[0] != 0xa1 {
		t.Fatal("output reused caller backing")
	}
}

func TestCryptoInputPreflightRejectsBeforeOutputAllocation(t *testing.T) {
	if _, err := handshakeWire(); err != nil {
		t.Fatal(err)
	}
	values := map[string][]byte{"profile": []byte(protocolv4.DHProfileX25519), "handshake_hash": make([]byte, 32), "context_digest": make([]byte, 32), "rekey_id": make([]byte, 16)}
	numbers := map[string]uint64{"epoch": 0, "next_epoch": 1, "phase": 1, "role": 0}
	for _, fault := range []string{"missing", "length", "ascii", "enum", "integer"} {
		t.Run(fault, func(t *testing.T) {
			savedProfile, savedID, savedRole, savedEpoch := values["profile"], values["rekey_id"], numbers["role"], numbers["next_epoch"]
			defer func() {
				values["profile"], values["rekey_id"], numbers["role"], numbers["next_epoch"] = savedProfile, savedID, savedRole, savedEpoch
			}()
			switch fault {
			case "missing":
				delete(values, "rekey_id")
			case "length":
				values["rekey_id"] = savedID[:15]
			case "ascii":
				values["profile"] = []byte{0xff}
			case "enum":
				numbers["role"] = 2
			case "integer":
				numbers["next_epoch"] = uint64(math.MaxUint32) + 1
			}
			allocations := testing.AllocsPerRun(5, func() {
				out, err := cryptoInput("rekey_confirm_key", values, numbers)
				if !errors.Is(err, ErrConfiguration) || out != nil {
					t.Fatal("invalid input reached output allocation", err)
				}
			})
			if allocations != 0 {
				t.Fatal("invalid input allocated output", allocations)
			}
		})
	}
	r, _ := handshakeWire()
	d := r.domains["rekey_confirm_key"]
	_, size, err := encodeCryptoInput(r, d, values, numbers, nil)
	if err != nil {
		t.Fatal(err)
	}
	short := make([]byte, 0, size-1)
	if out, _, err := encodeCryptoInput(r, d, values, numbers, short); !errors.Is(err, ErrConfiguration) || out != nil {
		t.Fatal("short output silently grew", err)
	}
	w := cryptoInputWriter{size: math.MaxInt}
	if err := w.write([]byte{1}); !errors.Is(err, ErrConfiguration) || w.size != math.MaxInt {
		t.Fatal("input size overflow was not refused", err)
	}
}
