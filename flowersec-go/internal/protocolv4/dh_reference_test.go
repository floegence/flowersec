package protocolv4

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestV4ProfileDHReference(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/profile_dh.json")
	if err != nil {
		t.Fatal(err)
	}
	type vector struct {
		ID      string `json:"id"`
		Profile string `json:"profile"`
		Private string `json:"private_hex"`
		Public  string `json:"public_hex"`
		Shared  string `json:"shared_hex"`
		Accept  bool   `json:"accept"`
	}
	var corpus struct {
		SchemaSHA string   `json:"schema_sha256"`
		Revision  int      `json:"policy_revision"`
		Vectors   []vector `json:"vectors"`
		Keys      []vector `json:"keys"`
	}
	var policy struct {
		Revision int `json:"revision"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(DHPolicyJSON), &policy); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaSHA != SchemaSHA256 || corpus.Revision != policy.Revision || len(corpus.Vectors) == 0 || len(corpus.Keys) == 0 {
		t.Fatal("DH corpus binding drift")
	}
	for _, v := range append(corpus.Vectors, corpus.Keys...) {
		t.Run(v.ID, func(t *testing.T) {
			private, public := signatureHex(t, v.Private), signatureHex(t, v.Public)
			beforePrivate, beforePublic := bytes.Clone(private), bytes.Clone(public)
			var output, expected []byte
			var err error
			if strings.HasPrefix(v.ID, "dh_key_") {
				output, err = dhPublicReference(v.Profile, private)
				expected = public
			} else {
				output, err = dhReference(v.Profile, private, public)
				expected = signatureHex(t, v.Shared)
			}
			if v.Accept {
				if err != nil || !bytes.Equal(output, expected) {
					t.Fatalf("output differs: %x, %v", output, err)
				}
			} else if !errors.Is(err, errDHReference) || output != nil {
				t.Fatal("invalid DH material escaped")
			}
			if !bytes.Equal(private, beforePrivate) || !bytes.Equal(public, beforePublic) {
				t.Fatal("DH altered original inputs")
			}
		})
	}
	if output, err := dhReference("unregistered", make([]byte, 32), make([]byte, 32)); output != nil || !errors.Is(err, errDHReference) {
		t.Fatal("unknown profile accepted")
	}
}
