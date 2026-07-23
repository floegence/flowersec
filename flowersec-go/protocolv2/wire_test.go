package protocolv2_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/protocolv2"
)

func TestSetupPrefaceExactWire(t *testing.T) {
	var mac [32]byte
	for i := range mac {
		mac[i] = byte(i)
	}
	want := mustHex(t,
		"46535332"+
			"02"+
			"01"+
			"0000"+
			"0000000000000001"+
			"00000007"+
			"00000000"+
			"000102030405060708090a0b0c0d0e0f"+
			"101112131415161718191a1b1c1d1e1f",
	)

	raw, err := (protocolv2.SetupPreface{
		OpenerRole:      protocolv2.RoleClient,
		LogicalStreamID: 1,
		InitialEpoch:    7,
		SetupMAC:        mac,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("wire = %x, want %x", raw, want)
	}

	got, err := protocolv2.ParseSetupPreface(raw)
	if err != nil {
		t.Fatalf("ParseSetupPreface: %v", err)
	}
	if got.OpenerRole != protocolv2.RoleClient || got.LogicalStreamID != 1 || got.InitialEpoch != 7 || got.SetupMAC != mac {
		t.Fatalf("parsed = %+v", got)
	}
}

func TestSetupPrefaceRejectsReservedRoleParityAndLength(t *testing.T) {
	valid, err := (protocolv2.SetupPreface{OpenerRole: protocolv2.RoleClient, LogicalStreamID: 1}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	for name, mutate := range map[string]func([]byte) []byte{
		"short":    func(b []byte) []byte { return b[:len(b)-1] },
		"magic":    func(b []byte) []byte { b[0] = 'X'; return b },
		"version":  func(b []byte) []byte { b[4] = 3; return b },
		"flags":    func(b []byte) []byte { b[7] = 1; return b },
		"reserved": func(b []byte) []byte { b[23] = 1; return b },
		"parity":   func(b []byte) []byte { b[15] = 2; return b },
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutate(bytes.Clone(valid))
			if _, err := protocolv2.ParseSetupPreface(raw); !errors.Is(err, protocolv2.ErrInvalidSetupPreface) {
				t.Fatalf("error = %v, want ErrInvalidSetupPreface", err)
			}
		})
	}
}

func TestRecordHeaderExactWireAndBounds(t *testing.T) {
	want := mustHex(t, "465352320218000000000007000000000000000900000010")
	header := protocolv2.RecordHeader{Epoch: 7, Sequence: 9, CiphertextLength: 16}
	raw, err := header.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("wire = %x, want %x", raw, want)
	}
	got, err := protocolv2.ParseRecordHeader(raw)
	if err != nil || got != header {
		t.Fatalf("ParseRecordHeader = %+v, %v", got, err)
	}

	header.CiphertextLength = protocolv2.MaxCiphertextBytes + 1
	if _, err := header.MarshalBinary(); !errors.Is(err, protocolv2.ErrRecordTooLarge) {
		t.Fatalf("oversize error = %v, want ErrRecordTooLarge", err)
	}
}

func TestInnerRecordExactWire(t *testing.T) {
	want := mustHex(t, "0400000000000003616263")
	raw, err := protocolv2.MarshalInnerRecord(protocolv2.InnerData, []byte("abc"))
	if err != nil {
		t.Fatalf("MarshalInnerRecord: %v", err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("wire = %x, want %x", raw, want)
	}
	typ, payload, err := protocolv2.ParseInnerRecord(raw)
	if err != nil || typ != protocolv2.InnerData || string(payload) != "abc" {
		t.Fatalf("ParseInnerRecord = %d %q %v", typ, payload, err)
	}

	if _, err := protocolv2.MarshalInnerRecord(protocolv2.InnerData, nil); !errors.Is(err, protocolv2.ErrInvalidInnerRecord) {
		t.Fatalf("empty DATA error = %v", err)
	}
	if _, _, err := protocolv2.ParseInnerRecord([]byte{255, 0, 0, 0, 0, 0, 0, 0}); !errors.Is(err, protocolv2.ErrUnknownInnerType) {
		t.Fatalf("unknown type error = %v", err)
	}
}

func TestInnerRecordFixedPayloadSizes(t *testing.T) {
	cases := []struct {
		typ  protocolv2.InnerType
		size int
	}{
		{protocolv2.InnerOpenACK, 32},
		{protocolv2.InnerOpenReject, 34},
		{protocolv2.InnerStreamKeyUpdate, 12},
		{protocolv2.InnerPing, 8},
		{protocolv2.InnerPong, 8},
		{protocolv2.InnerSessionKeyUpdate, 20},
		{protocolv2.InnerStreamReset, 10},
		{protocolv2.InnerGoAway, 10},
		{protocolv2.InnerSessionClose, 2},
		{protocolv2.InnerSessionKeyUpdateACK, 20},
		{protocolv2.InnerStreamKeyUpdateACK, 20},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("type_%d", tc.typ), func(t *testing.T) {
			if _, err := protocolv2.MarshalInnerRecord(tc.typ, make([]byte, tc.size)); err != nil {
				t.Fatalf("valid size: %v", err)
			}
			for _, bad := range []int{tc.size - 1, tc.size + 1} {
				if _, err := protocolv2.MarshalInnerRecord(tc.typ, make([]byte, bad)); !errors.Is(err, protocolv2.ErrInvalidInnerRecord) {
					t.Fatalf("size %d error = %v", bad, err)
				}
			}
		})
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
