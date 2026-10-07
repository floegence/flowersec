package ledgerv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// The corpus supplies canonical public history. Reading this fixture does not
// authenticate its signer or create a production activation capability.
func storedPoolFixture(t *testing.T, s *SQLiteStore) (key, projection []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []struct{ ID, Hex string } }
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	var proof []byte
	for _, v := range corpus.Vectors {
		if v.ID == "activation_pool_fields" {
			proof, err = hex.DecodeString(v.Hex)
			break
		}
	}
	if err != nil || len(proof) == 0 {
		t.Fatal("missing pool history fixture", err)
	}
	d, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := d.DecodeMap(proof, "ActivationAuthorization", protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	get := func(name string) protocolv4.Value { return doc.Root().Named("ActivationAuthorization", name) }
	text := func(v protocolv4.Value) string { text, _ := v.Text(); return text }
	data := func(v protocolv4.Value) []byte { b, _ := v.ByteString(); return b }
	number := func(v protocolv4.Value) uint64 { n, _ := v.Uint(); return n }
	selection := get("candidate_selection")
	once := selection.Named("PoolSelectionRef", "once_authority_ref")
	budget := selection.Named("PoolSelectionRef", "attempt_budget")
	per := budget.Named("PoolAttemptBudget", "per_candidate")
	issued, activation, session := number(get("issued_at_ms")), number(get("activation_not_after_ms")), number(get("session_not_after_ms"))
	var domains []struct {
		Name  string
		Label string `json:"label_bytes"`
	}
	if err := json.Unmarshal([]byte(protocolv4.DomainRegistryJSON), &domains); err != nil {
		t.Fatal(err)
	}
	var label []byte
	for _, domain := range domains {
		if domain.Name == "activation_digest" {
			label, err = hex.DecodeString(domain.Label)
			break
		}
	}
	if err != nil || len(label) == 0 {
		t.Fatal("missing activation digest domain", err)
	}
	h := sha256.New()
	_, _ = h.Write(label)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(proof)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(proof)
	projection = make([]byte, 4096)
	w := admissionWriter{dst: projection}
	w.text("flowersec/pool-consume/1")
	for _, n := range []uint64{1, s.epoch, s.identity.Generation, 1, activation, issued, issued, activation, session, number(selection.Named("PoolSelectionRef", "candidate_indices").Index(0)), number(per.Named("CandidateAttemptBudget", "address_attempts")), number(per.Named("CandidateAttemptBudget", "preauth_bytes")), number(per.Named("CandidateAttemptBudget", "work_units")), number(budget.Named("PoolAttemptBudget", "total_address_attempts")), number(budget.Named("PoolAttemptBudget", "total_preauth_bytes")), number(budget.Named("PoolAttemptBudget", "total_work_units")), number(budget.Named("PoolAttemptBudget", "parallel_candidates"))} {
		w.uint(n)
	}
	tenant := text(get("tenant_id"))
	issuer, lease := data(get("artifact_issuer_key_id")), data(get("lease_id"))
	for _, value := range []string{s.identity.Authority, tenant, text(get("audience")), "test-profile", text(get("authority_id")), text(once.Named("OnceAuthorityRef", "winner_authority_id")), text(get("signing_key_id"))} {
		w.text(value)
	}
	for _, value := range [][]byte{s.identity.StoreID[:], bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), issuer, lease, data(get("attempt_id")), bytes.Repeat([]byte{3}, 16), bytes.Repeat([]byte{4}, 32), data(get("artifact_digest")), h.Sum(nil), bytes.Repeat([]byte{5}, 32), data(get("client_identity_digest")), data(get("server_identity_digest")), data(selection.Named("PoolSelectionRef", "candidate_set_digest")), data(get("route_selection"))} {
		w.bytes(value)
	}
	w.uint(uint64(len(proof)))
	w.bytes(proof)
	if w.err != nil {
		t.Fatal(w.err)
	}
	key = append([]byte{byte(len(tenant))}, []byte(tenant)...)
	key = append(key, issuer...)
	key = append(key, lease...)
	return key, projection[:w.n]
}

func TestSQLiteCurrentPoolHistoryRefusesFactAndProofMutations(t *testing.T) {
	for _, mode := range []string{"current", "key", "fence", "trailing", "proof"} {
		t.Run(mode, func(t *testing.T) {
			f := newSQLiteFixture(t, "")
			s := f.create()
			key, projection := storedPoolFixture(t, s)
			switch mode {
			case "key":
				key[len(key)-1] ^= 1
			case "fence":
				binary.BigEndian.PutUint64(projection[2+len("flowersec/pool-consume/1")+8:], s.epoch+1)
			case "trailing":
				projection = append(projection, 0)
			case "proof":
				projection[len(projection)-1] ^= 1
			}
			if err := s.exec("INSERT INTO spend VALUES(?1,1,1,?2,?3,?4)", named(1, key), named(2, sqliteUint(1)), named(3, sqliteUint(s.epoch)), named(4, projection)); err != nil {
				t.Fatal(err)
			}
			if err := s.exec("UPDATE manifest SET spend_rows=1"); err != nil {
				t.Fatal(err)
			}
			closeSQLite(t, s)
			before, err := os.ReadFile(f.backing.path)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := f.open(false)
			if mode == "current" {
				if err != nil {
					t.Fatal("valid consume history refused", err)
				}
				closeSQLite(t, opened)
				return
			}
			if opened != nil {
				t.Fatal("damaged history restored a store owner")
			}
			storageFormatProjection(t, err)
			after, err := os.ReadFile(f.backing.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal rewrote history", err)
			}
		})
	}
}

func TestSQLiteCurrentRelayReservationKeepsUnknownHistory(t *testing.T) {
	for _, damaged := range []bool{false, true} {
		f := newSQLiteFixtureWithLimits(t, "", SQLiteLimits{MaxPages: 128, MaxRecords: 16, MaxRecordBytes: 65536, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})
		s := f.create()
		var keyBuffer [193]byte
		var sourceBuffer [338]byte
		key, err := relayRegistrationKey(keyBuffer[:], protocolv4.RelayParentKey{Tenant: "tenant", Issuer: [16]byte{1}, Lease: [16]byte{2}, Candidate: [16]byte{3}, Attempt: [16]byte{4}})
		if err != nil {
			t.Fatal(err)
		}
		sources, err := relayRegistrationSources(sourceBuffer[:], [2]SQLiteIdentity{s.identity, s.identity})
		if err != nil {
			t.Fatal(err)
		}
		projection := make([]byte, 65536)
		if damaged {
			projection[len(projection)-1] = 1
		}
		if err := s.exec("INSERT INTO relay_issuance VALUES(?1,?2,0,?3,zeroblob(32),?4)", named(1, key), named(2, sources), named(3, bytes.Repeat([]byte{1}, 16)), named(4, projection)); err != nil {
			t.Fatal(err)
		}
		if err := s.exec("UPDATE manifest SET relay_rows=1"); err != nil {
			t.Fatal(err)
		}
		closeSQLite(t, s)
		opened, err := f.open(false)
		if damaged {
			if opened != nil {
				t.Fatal("nonzero reservation restored owner")
			}
			storageFormatProjection(t, err)
		} else {
			if err != nil {
				t.Fatal("unknown original reservation refused", err)
			}
			closeSQLite(t, opened)
		}
	}
}
