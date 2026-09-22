package protocolv4

// Public READY fixtures only. No credential trust, one-shot handshake owner,
// dual-READY publication or live authorization/resource gate is established.
import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
)

type readyField struct {
	Name, Type string
	Length     int
	Bitmask    *uint64
	Enum       map[string]uint64
}
type readyMapDefinition struct {
	Fields map[string]readyField
}
type readyReference struct {
	maps map[string]readyMapDefinition
}

func readyHead(major byte, value uint64) []byte {
	if value < 24 {
		return []byte{major<<5 | byte(value)}
	}
	for _, size := range []struct {
		width int
		ai    byte
	}{{1, 24}, {2, 25}, {4, 26}, {8, 27}} {
		if size.width == 8 || value < uint64(1)<<(size.width*8) {
			encoded := binary.BigEndian.AppendUint64(nil, value)
			return append([]byte{major<<5 | size.ai}, encoded[8-size.width:]...)
		}
	}
	panic("uint64 encoding")
}

func readyFields(def readyMapDefinition) []uint64 {
	ids := make([]uint64, 0, len(def.Fields))
	for text := range def.Fields {
		id, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			panic(err)
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (r readyReference) encode(name string, context map[string]any) ([]byte, error) {
	def, exists := r.maps[name]
	if !exists {
		return nil, fmt.Errorf("missing READY map")
	}
	out := readyHead(5, uint64(len(def.Fields)))
	for _, id := range readyFields(def) {
		field := def.Fields[strconv.FormatUint(id, 10)]
		out = append(out, readyHead(0, id)...)
		switch field.Type {
		case "bytes":
			s, ok := context[field.Name+"_hex"].(string)
			if !ok {
				return nil, fmt.Errorf("missing bytes")
			}
			value, err := hex.DecodeString(s)
			if err != nil || len(value) != field.Length {
				return nil, fmt.Errorf("invalid byte length")
			}
			out = append(out, readyHead(2, uint64(len(value)))...)
			out = append(out, value...)
		case "text":
			value, ok := context[field.Name].(string)
			if !ok {
				return nil, fmt.Errorf("missing text")
			}
			if value != DHProfileX25519 && value != DHProfileP256 {
				return nil, fmt.Errorf("unknown profile")
			}
			out = append(out, readyHead(3, uint64(len(value)))...)
			out = append(out, []byte(value)...)
		case "uint8", "uint64":
			value, ok := context[field.Name].(float64)
			if !ok || value < 0 || value > 9007199254740991 || value != float64(uint64(value)) {
				return nil, fmt.Errorf("invalid fixture integer")
			}
			n := uint64(value)
			if field.Type == "uint8" && n > 255 || field.Bitmask != nil && n & ^*field.Bitmask != 0 {
				return nil, fmt.Errorf("integer range")
			}
			if len(field.Enum) > 0 {
				found := false
				for _, v := range field.Enum {
					found = found || v == n
				}
				if !found {
					return nil, fmt.Errorf("enum")
				}
			}
			out = append(out, readyHead(0, n)...)
		default:
			return nil, fmt.Errorf("unsupported READY field")
		}
	}
	return out, nil
}

func (r readyReference) decode(wire []byte) (map[string]any, error) {
	def := r.maps["READY"]
	out := map[string]any{}
	take := func(expected []byte) bool {
		if !bytes.HasPrefix(wire, expected) {
			return false
		}
		wire = wire[len(expected):]
		return true
	}
	if !take(readyHead(5, uint64(len(def.Fields)))) {
		return nil, fmt.Errorf("READY map")
	}
	for _, id := range readyFields(def) {
		field := def.Fields[strconv.FormatUint(id, 10)]
		if field.Type != "bytes" || !take(readyHead(0, id)) || !take(readyHead(2, uint64(field.Length))) || len(wire) < field.Length {
			return nil, fmt.Errorf("READY field")
		}
		out[field.Name+"_hex"] = hex.EncodeToString(wire[:field.Length])
		wire = wire[field.Length:]
	}
	if len(wire) != 0 {
		return nil, fmt.Errorf("READY suffix")
	}
	return out, nil
}

func (r readyReference) material(context map[string]any, proof []byte) (map[string][]byte, error) {
	proofInput, err := r.encode("ReadyProofInput", context)
	if err != nil {
		return nil, err
	}
	message, err := recordDomain("ready_identity", map[string][]byte{"proof": proofInput}, nil)
	if err != nil {
		return nil, err
	}
	decode := func(name string) []byte { s, _ := context[name].(string); b, _ := hex.DecodeString(s); return b }
	role, ok := context["role"].(float64)
	if !ok {
		return nil, fmt.Errorf("role")
	}
	profile, ok := context["crypto_profile_id"].(string)
	if !ok {
		return nil, fmt.Errorf("profile")
	}
	info, err := recordDomain("ready_key", map[string][]byte{"profile": []byte(profile), "handshake_hash": decode("handshake_hash_hex"), "context_digest": decode("transport_context_digest_hex")}, map[string]uint64{"role": uint64(role)})
	if err != nil {
		return nil, err
	}
	root := decode("epoch_root_hex")
	if len(root) != 32 {
		return nil, fmt.Errorf("root")
	}
	key, err := hkdf.Expand(sha256.New, root, string(info), 32)
	if err != nil {
		return nil, err
	}
	values := map[string]any{}
	for k, v := range context {
		values[k] = v
	}
	values["identity_proof_hex"] = hex.EncodeToString(proof)
	macInput, err := r.encode("ReadyMACInput", values)
	if err != nil {
		return nil, err
	}
	macMessage, err := recordDomain("ready_mac", map[string][]byte{"mac_input": macInput}, nil)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(macMessage)
	return map[string][]byte{"proof_input_hex": proofInput, "signature_message_hex": message, "key_info_hex": info, "key_hex": key, "mac_input_hex": macInput, "mac_message_hex": macMessage, "confirmation_mac_hex": mac.Sum(nil)}, nil
}

func (r readyReference) verify(context map[string]any, wire []byte) bool {
	received, err := r.decode(wire)
	if err != nil {
		return false
	}
	proof, _ := hex.DecodeString(received["identity_proof_hex"].(string))
	mac, _ := hex.DecodeString(received["confirmation_mac_hex"].(string))
	material, err := r.material(context, proof)
	if err != nil {
		return false
	}
	keyText, _ := context["public_key_hex"].(string)
	key, err := hex.DecodeString(keyText)
	return err == nil && hmac.Equal(mac, material["confirmation_mac_hex"]) && VerifyEd25519(proof, material["signature_message_hex"], key)
}

func TestV4ReadySharedCorpus(t *testing.T) {
	var corpus struct {
		Schema    string `json:"schema_sha256"`
		Vectors   []map[string]json.RawMessage
		Negatives []struct {
			ID, Source string
			Wire       string         `json:"ready_hex"`
			Patch      map[string]any `json:"context_patch"`
			Error      string         `json:"expected_error"`
		}
	}
	raw, err := os.ReadFile("../../../testdata/transport_v4/ready.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != SchemaSHA256 || len(corpus.Vectors) != 8 || len(corpus.Negatives) == 0 {
		t.Fatal("READY corpus binding/coverage")
	}
	r := readyReference{}
	if err = json.Unmarshal([]byte(ReadyRegistryJSON), &r.maps); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Envelope struct{ Layout []recordField }
	}
	if err = json.Unmarshal([]byte(RecordRegistryJSON), &envelope); err != nil {
		t.Fatal(err)
	}
	contexts := map[string]map[string]any{}
	for _, v := range corpus.Vectors {
		str := func(name string) string {
			var s string
			if err := json.Unmarshal(v[name], &s); err != nil {
				t.Fatal(name, err)
			}
			return s
		}
		id := str("id")
		var context map[string]any
		if err = json.Unmarshal(v["context"], &context); err != nil {
			t.Fatal(err)
		}
		contexts[id] = context
		proof := noiseHex(t, str("identity_proof_hex"))
		material, err := r.material(context, proof)
		if err != nil {
			t.Fatal(err)
		}
		for name, actual := range material {
			if hex.EncodeToString(actual) != str(name) {
				t.Fatal(id, name)
			}
		}
		signature, err := strictEd25519SignReference(material["signature_message_hex"], noiseHex(t, str("signing_seed_hex")))
		if err != nil || !bytes.Equal(signature, proof) {
			t.Fatal(id, "signer", err)
		}
		ready, err := r.encode("READY", map[string]any{"identity_proof_hex": hex.EncodeToString(proof), "confirmation_mac_hex": hex.EncodeToString(material["confirmation_mac_hex"])})
		if err != nil {
			t.Fatal(err)
		}
		header, err := recordLayout(envelope.Envelope.Layout, map[string]uint64{"payload_length": uint64(len(ready)), "frame_type": uint64(FrameReady)})
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(ready) != str("ready_hex") || hex.EncodeToString(header) != str("envelope_header_hex") || hex.EncodeToString(bytes.Join([][]byte{header, ready}, nil)) != str("wire_hex") || !r.verify(context, ready) {
			t.Fatal(id, "READY bytes/verification")
		}
	}
	for _, n := range corpus.Negatives {
		source, exists := contexts[n.Source]
		if !exists || n.Error != "ready_rejected" {
			t.Fatal(n.ID, "negative binding")
		}
		context := map[string]any{}
		for k, v := range source {
			context[k] = v
		}
		for k, v := range n.Patch {
			context[k] = v
		}
		if r.verify(context, noiseHex(t, n.Wire)) {
			t.Fatal(n.ID, "accepted")
		}
	}
}
