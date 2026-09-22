package protocolv4

// Public fixed transactions only. Exact expected-message matching is not a
// general receiver codec, barrier proof, epoch installation or publisher gate.
import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type rekeyDefinition struct {
	Role   uint64 `json:"sender_role"`
	MAC    uint64 `json:"mac_field"`
	Fields map[string]struct {
		Name, Type    string
		Length        int
		Const         *uint64
		ProfilePublic bool `json:"profile_public_key"`
		Items         struct {
			Schema string `json:"schema_ref"`
		}
	}
}
type rekeyContext struct {
	Profile string `json:"profile"`
	Hash    string `json:"handshake_hash_hex"`
	Digest  string `json:"context_digest_hex"`
	Epoch   uint64 `json:"epoch"`
	Next    uint64 `json:"next_epoch"`
	ID      string `json:"rekey_id_hex"`
}
type rekeyPhase struct {
	ID, Schema  string
	Phase, Role uint64
	Base        string `json:"base_hex"`
	Message     string `json:"message_hex"`
	Unsigned    string `json:"unsigned_hex"`
	KeyInfo     string `json:"key_info_hex"`
	Key         string `json:"key_hex"`
	MACMessage  string `json:"mac_message_hex"`
	MAC         string `json:"confirmation_mac_hex"`
	Expected    map[string]string
	Record      recordVector
}
type rekeyRound struct {
	ID         string
	Context    rekeyContext
	Input      map[string]json.RawMessage
	Phases     []rekeyPhase
	Old        string `json:"old_root_hex"`
	New        string `json:"new_root_hex"`
	Secret     string `json:"secret_hex"`
	DH         string `json:"dh_hex"`
	PRK        string `json:"prk_hex"`
	InitDigest string `json:"init_digest_hex"`
	Transcript string `json:"transcript_hex"`
}

func rekeyEncode(reg map[string]rekeyDefinition, name, profile string, values map[string]any, unsigned bool) ([]byte, error) {
	def, ok := reg[name]
	if !ok {
		return nil, fmt.Errorf("missing map")
	}
	ids := []int{}
	for key := range def.Fields {
		n, err := strconv.Atoi(key)
		if err != nil {
			return nil, err
		}
		if !unsigned || uint64(n) != def.MAC {
			ids = append(ids, n)
		}
	}
	sort.Ints(ids)
	out := readyHead(5, uint64(len(ids)))
	for _, id := range ids {
		f := def.Fields[strconv.Itoa(id)]
		value, ok := values[f.Name]
		if !ok {
			return nil, fmt.Errorf("missing field %s", f.Name)
		}
		out = append(out, readyHead(0, uint64(id))...)
		switch {
		case strings.HasPrefix(f.Type, "uint"):
			n, ok := value.(uint64)
			bits, err := strconv.Atoi(strings.TrimPrefix(f.Type, "uint"))
			if !ok || err != nil || bits < 64 && n >= uint64(1)<<bits || f.Const != nil && n != *f.Const {
				return nil, fmt.Errorf("integer field")
			}
			out = append(out, readyHead(0, n)...)
		case f.Type == "bytes":
			b, ok := value.([]byte)
			length := f.Length
			if f.ProfilePublic {
				_, length, _ = dhReferenceCurve(profile)
			}
			if !ok || len(b) != length {
				return nil, fmt.Errorf("byte field")
			}
			out = append(out, readyHead(2, uint64(len(b)))...)
			out = append(out, b...)
		case f.Type == "array":
			list, ok := value.([]map[string]any)
			if !ok {
				return nil, fmt.Errorf("barrier array")
			}
			out = append(out, readyHead(4, uint64(len(list)))...)
			for _, item := range list {
				b, err := rekeyEncode(reg, f.Items.Schema, profile, item, false)
				if err != nil {
					return nil, err
				}
				out = append(out, b...)
			}
		default:
			return nil, fmt.Errorf("unsupported field")
		}
	}
	return out, nil
}

func rekeyDomain(c rekeyContext, name string, phase, role uint64, extra map[string][]byte) ([]byte, error) {
	b := map[string][]byte{"profile": []byte(c.Profile)}
	for name, s := range map[string]string{"handshake_hash": c.Hash, "context_digest": c.Digest, "rekey_id": c.ID} {
		v, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		b[name] = v
	}
	maps.Copy(b, extra)
	return recordDomain(name, b, map[string]uint64{"epoch": c.Epoch, "next_epoch": c.Next, "phase": phase, "role": role})
}
func rekeyExpand(key, info []byte) []byte {
	b, err := hkdf.Expand(sha256.New, key, string(info), 32)
	if err != nil {
		panic(err)
	}
	return b
}
func rekeyHMAC(key, info []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(info)
	return h.Sum(nil)
}
func rekeyHash(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func rekeyMessage(reg map[string]rekeyDefinition, c rekeyContext, p rekeyPhase, base []byte, values map[string]any) ([]byte, map[string][]byte, error) {
	if c.Next != c.Epoch+1 || c.Next > uint64(^uint32(0)) || len(base) != 32 {
		return nil, nil, fmt.Errorf("epoch/base")
	}
	def := reg[p.Schema]
	values = maps.Clone(values)
	values["phase"] = p.Phase
	values["next_epoch"] = c.Next
	var err error
	values["rekey_id"], err = hex.DecodeString(c.ID)
	if err != nil {
		return nil, nil, err
	}
	u, err := rekeyEncode(reg, p.Schema, c.Profile, values, true)
	if err != nil {
		return nil, nil, err
	}
	info, err := rekeyDomain(c, "rekey_confirm_key", p.Phase, def.Role, nil)
	if err != nil {
		return nil, nil, err
	}
	key := rekeyExpand(base, info)
	msg, err := rekeyDomain(c, "rekey_confirm_mac", p.Phase, def.Role, map[string][]byte{"message": u})
	if err != nil {
		return nil, nil, err
	}
	mac := rekeyHMAC(key, msg)
	values["confirmation_mac"] = mac
	wire, err := rekeyEncode(reg, p.Schema, c.Profile, values, false)
	return wire, map[string][]byte{"unsigned_hex": u, "key_info_hex": info, "key_hex": key, "mac_message_hex": msg, "confirmation_mac_hex": mac}, err
}

func TestV4RekeySharedCorpus(t *testing.T) {
	var corpus struct {
		Schema    string `json:"schema_sha256"`
		Rounds    []rekeyRound
		Negatives []struct {
			ID, Source string
			Message    string                     `json:"message_hex"`
			Base       string                     `json:"base_hex"`
			Patch      map[string]json.RawMessage `json:"context_patch"`
			Expected   map[string]string
		}
	}
	raw, err := os.ReadFile("../../../testdata/transport_v4/rekey.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != SchemaSHA256 || len(corpus.Rounds) != 4 || len(corpus.Negatives) == 0 {
		t.Fatal("rekey corpus binding")
	}
	var reg map[string]rekeyDefinition
	if err = json.Unmarshal([]byte(RekeyRegistryJSON), &reg); err != nil {
		t.Fatal(err)
	}
	var records struct {
		Envelope      struct{ Layout []recordField }
		Header, Nonce []recordField
		Profiles      map[string]struct {
			Algorithm string `json:"record_aead"`
			Tag       uint64 `json:"tag_bytes"`
		}
	}
	if err = json.Unmarshal([]byte(RecordRegistryJSON), &records); err != nil {
		t.Fatal(err)
	}
	type match struct {
		context rekeyContext
		phase   rekeyPhase
		values  map[string]any
	}
	byID := map[string]match{}
	previous := map[string]string{}
	for _, r := range corpus.Rounds {
		c := r.Context
		check := func(actual []byte, want string) {
			t.Helper()
			if hex.EncodeToString(actual) != want {
				t.Fatalf("%s bytes differ", r.ID)
			}
		}
		get := func(name string) string {
			var s string
			if err := json.Unmarshal(r.Input[name], &s); err != nil {
				t.Fatal(err)
			}
			return s
		}
		b := func(s string) []byte { return noiseHex(t, s) }
		domain := func(name string, extra map[string][]byte) []byte {
			v, err := rekeyDomain(c, name, 0, 0, extra)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		if c.Epoch > 0 && previous[c.Profile] != r.Old {
			t.Fatal("root continuity")
		}
		cp, err := dhPublicReference(c.Profile, b(get("client_private_hex")))
		if err != nil {
			t.Fatal(err)
		}
		sp, err := dhPublicReference(c.Profile, b(get("server_private_hex")))
		if err != nil {
			t.Fatal(err)
		}
		dh, err := dhReference(c.Profile, b(get("client_private_hex")), sp)
		if err != nil {
			t.Fatal(err)
		}
		check(dh, r.DH)
		other, err := dhReference(c.Profile, b(get("server_private_hex")), cp)
		if err != nil || !bytes.Equal(dh, other) {
			t.Fatal("DH directions", err)
		}
		secret := rekeyExpand(b(r.Old), domain("rekey_secret", nil))
		check(secret, r.Secret)
		barrier := func(side string) []map[string]any {
			var entries []map[string]string
			if err := json.Unmarshal(r.Input[side+"_barrier"], &entries); err != nil {
				t.Fatal(err)
			}
			out := []map[string]any{}
			for _, e := range entries {
				item := map[string]any{}
				for k, v := range e {
					n, err := strconv.ParseUint(v, 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					item[k] = n
				}
				out = append(out, item)
			}
			return out
		}
		values := []map[string]any{{"client_ephemeral": cp, "client_barrier": barrier("client")}, {"server_ephemeral": sp, "server_barrier": barrier("server")}, {}, {}}
		var init, reply, root, transcript []byte
		for i, p := range r.Phases {
			base := secret
			if i == 1 {
				values[i]["init_digest"] = rekeyHash(domain("rekey_init_digest", map[string][]byte{"init": init}))
				check(values[i]["init_digest"].([]byte), r.InitDigest)
			}
			if i == 2 {
				transcript = rekeyHash(domain("rekey_transcript", map[string][]byte{"init": init, "reply": reply}))
				check(transcript, r.Transcript)
				prk := rekeyHMAC(secret, dh)
				check(prk, r.PRK)
				root = rekeyExpand(prk, domain("rekey_root", map[string][]byte{"transcript_digest": transcript}))
				check(root, r.New)
			}
			if i >= 2 {
				base = root
				values[i]["transcript_digest"] = transcript
				side := "client"
				if p.Role == 1 {
					side = "server"
				}
				seq, err := strconv.ParseUint(get(side+"_old_sequence"), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				values[i]["old_maintenance_next_sequence"] = seq + 1
			}
			wire, material, err := rekeyMessage(reg, c, p, base, values[i])
			if err != nil {
				t.Fatal(err)
			}
			check(wire, p.Message)
			check(base, p.Base)
			for k, want := range map[string]string{"unsigned_hex": p.Unsigned, "key_info_hex": p.KeyInfo, "key_hex": p.Key, "mac_message_hex": p.MACMessage, "confirmation_mac_hex": p.MAC} {
				check(material[k], want)
			}
			if i == 0 {
				init = wire
			}
			if i == 1 {
				reply = wire
			}
			byID[p.ID] = match{c, p, values[i]}
			epoch, recordRoot := c.Epoch, b(r.Old)
			side := "client"
			if p.Role == 1 {
				side = "server"
			}
			sequence, err := strconv.ParseUint(get(side+"_old_sequence"), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			if i >= 2 {
				epoch, recordRoot, sequence = c.Next, root, 0
			}
			if p.Record.Epoch != epoch || p.Record.Direction != reg[p.Schema].Role || p.Record.Sequence != sequence {
				t.Fatal("record phase")
			}
			ints := map[string]uint64{"epoch": epoch, "direction": p.Role, "sequence_scope": 0, "sequence": sequence}
			header, err := recordLayout(records.Header, ints)
			if err != nil {
				t.Fatal(err)
			}
			nonce, err := recordLayout(records.Nonce, ints)
			if err != nil {
				t.Fatal(err)
			}
			spec := records.Profiles[c.Profile]
			envelope, err := recordLayout(records.Envelope.Layout, map[string]uint64{"payload_length": uint64(len(header)+len(wire)) + spec.Tag, "frame_type": uint64(FrameRekey)})
			if err != nil {
				t.Fatal(err)
			}
			info, err := recordDomain("record_key", map[string][]byte{"profile": []byte(c.Profile), "handshake_hash": b(c.Hash)}, ints)
			if err != nil {
				t.Fatal(err)
			}
			key := rekeyExpand(recordRoot, info)
			aad, err := recordDomain("record_aad", map[string][]byte{"profile": []byte(c.Profile), "envelope_header": envelope, "record_header": header}, ints)
			if err != nil {
				t.Fatal(err)
			}
			aead, err := recordAEAD(spec.Algorithm, key)
			if err != nil {
				t.Fatal(err)
			}
			sealed := aead.Seal(nil, nonce, wire, aad)
			check(bytes.Join([][]byte{envelope, header, sealed}, nil), p.Record.Wire)
			opened, err := aead.Open(nil, nonce, sealed, aad)
			if err != nil || !bytes.Equal(opened, wire) {
				t.Fatal("record authentication", err)
			}
		}
		previous[c.Profile] = r.New
	}
	for _, n := range corpus.Negatives {
		m, ok := byID[n.Source]
		if !ok {
			t.Fatal("negative source")
		}
		raw, err := json.Marshal(m.context)
		if err != nil {
			t.Fatal(err)
		}
		var patched map[string]json.RawMessage
		if err = json.Unmarshal(raw, &patched); err != nil {
			t.Fatal(err)
		}
		maps.Copy(patched, n.Patch)
		raw, err = json.Marshal(patched)
		if err != nil {
			t.Fatal(err)
		}
		var c rekeyContext
		if err = json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		values := maps.Clone(m.values)
		for k, s := range n.Expected {
			if k == "old_maintenance_next_sequence" {
				v, err := strconv.ParseUint(s, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				values[k] = v
			} else {
				values[k] = noiseHex(t, s)
			}
		}
		wire, _, err := rekeyMessage(reg, c, m.phase, noiseHex(t, n.Base), values)
		if err == nil && bytes.Equal(wire, noiseHex(t, n.Message)) {
			t.Fatal("negative matched", n.ID)
		}
	}
}
