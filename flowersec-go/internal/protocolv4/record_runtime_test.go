package protocolv4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestRecordRuntimeSharedBytes(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/records.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []recordVector }
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, v := range corpus.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			hexBytes := func(value string) []byte {
				out, err := hex.DecodeString(value)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			header := RecordHeader{Epoch: uint32(v.Epoch), Scope: v.Scope, Sequence: v.Sequence}
			plain := hexBytes(v.Plaintext)
			prefix, err := RecordPrefix(FrameType(v.FrameType), header, len(plain), v.Profile, MaxPayloadLength)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(prefix, append(hexBytes(v.Envelope), hexBytes(v.Header)...)) {
				t.Fatal("prefix mismatch")
			}
			nonce, err := RecordNonce(header)
			if err != nil || !bytes.Equal(nonce[:], hexBytes(v.Nonce)) {
				t.Fatal("nonce mismatch", err)
			}
			var hash [32]byte
			copy(hash[:], hexBytes(v.Hash))
			info, err := RecordKeyInfo(v.Profile, hash, header.Epoch, Direction(v.Direction), header.Scope)
			if err != nil || !bytes.Equal(info, hexBytes(v.KeyInfo)) {
				t.Fatal("key input mismatch", err)
			}
			aad, err := RecordAAD(v.Profile, Direction(v.Direction), prefix)
			if err != nil || !bytes.Equal(aad, hexBytes(v.AAD)) {
				t.Fatal("AAD mismatch", err)
			}
			frame, decoded, ciphertext, err := ParseRecord(hexBytes(v.Wire), v.Profile, MaxPayloadLength)
			if err != nil || frame != FrameType(v.FrameType) || decoded != header || !bytes.Equal(ciphertext, hexBytes(v.Ciphertext)) {
				t.Fatal("record parsing mismatch", err)
			}
		})
	}
}
