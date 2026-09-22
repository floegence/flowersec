package cryptov4

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type testSigner struct{ key ed25519.PrivateKey }

func (s testSigner) PublicKey() []byte                 { return s.key.Public().(ed25519.PublicKey) }
func (s testSigner) Sign(input []byte) ([]byte, error) { return ed25519.Sign(s.key, input), nil }

func handshakePair(t *testing.T, profile string) (*Handshake, *Handshake) {
	t.Helper()
	return handshakePairWithClock(t, profile, cryptoClock(t, time.Now))
}

func handshakePairWithClock(t *testing.T, profile string, clock *timev4.Clock) (*Handshake, *Handshake) {
	t.Helper()
	return handshakePairWithIdle(t, profile, clock, 0)
}

func handshakePairWithIdle(t *testing.T, profile string, clock *timev4.Clock, idleMS uint64) (*Handshake, *Handshake) {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []struct{ ID, Hex string } }
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{}
	for _, v := range corpus.Vectors {
		if v.ID == "fsb_fields" || v.ID == "fsa_admitted_fields" {
			inputs[v.ID], err = hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	now, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	var configs [2]HandshakeConfig
	for role := range 2 {
		key, err := GenerateDHKey(profile)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Close)
		_, signing, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		deadline, err := timev4.NewAgeAt(clock, now, 60000, now.LowerMS+3600000)
		if err != nil {
			t.Fatal(err)
		}
		configs[role] = HandshakeConfig{Authorization: testAuthorization{}, Profile: profile, Role: protocolv4.Direction(role), PSK: [32]byte{1}, FSB: inputs["fsb_fields"], FSA: inputs["fsa_admitted_fields"], ContextDigest: [32]byte{2}, AdmissionBinding: [32]byte{3}, LocalCertificateDigest: [32]byte{byte(role + 4)}, LocalDH: key, LocalDHPublic: key.PublicKey(), Signer: testSigner{signing}, Features: 1, Deadline: deadline, SessionDeadlineMS: now.LowerMS + 3600000, Clock: clock}
		configs[role].Session = testSessionContract(t, profile, "transport", 4096, 4, idleMS, configs[role].SessionDeadlineMS)
		copy(configs[role].LocalEdPublic[:], signing.Public().(ed25519.PublicKey))
	}
	for role := range 2 {
		peer := configs[1-role]
		configs[role].PeerCertificateDigest = peer.LocalCertificateDigest
		configs[role].PeerDHPublic = peer.LocalDHPublic
		configs[role].PeerEdPublic = peer.LocalEdPublic
	}
	client, err := NewHandshake(configs[0])
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewHandshake(configs[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	t.Cleanup(server.Close)
	return client, server
}
func completeNoise(t *testing.T, client, server *Handshake) (*FinishedHandshake, *FinishedHandshake) {
	t.Helper()
	first, err := client.WriteMessage()
	if err != nil {
		t.Fatal(err)
	}
	if err = server.ReadMessage(first); err != nil {
		t.Fatal(err)
	}
	second, err := server.WriteMessage()
	if err != nil {
		t.Fatal(err)
	}
	if err = client.ReadMessage(second); err != nil {
		t.Fatal(err)
	}
	c, err := client.Finish()
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.Finish()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	t.Cleanup(s.Close)
	return c, s
}
func TestHandshakeProfilesThroughReadyAndRecords(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			client, server := handshakePair(t, profile)
			c, s := completeNoise(t, client, server)
			if c.Hash() != s.Hash() {
				t.Fatal("transcript mismatch")
			}
			if _, err := client.Finish(); !errors.Is(err, ErrHandshake) {
				t.Fatal("completion capability reused")
			}
			config := Config{MaxFrame: 4096, MaxScopes: 4, WorkSlots: 2, Datagrams: true, Maintenance: MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}}
			if _, err := c.StartRecords(); !errors.Is(err, ErrNotReady) {
				t.Fatal("published before dual READY", err)
			}
			ce, err := c.PrepareRecords(config)
			if err != nil {
				t.Fatal(err)
			}
			se, err := s.PrepareRecords(config)
			if err != nil {
				t.Fatal(err)
			}
			cr, err := c.Ready()
			if err != nil {
				t.Fatal(err)
			}
			sr, err := s.Ready()
			if err != nil {
				t.Fatal(err)
			}
			if len(cr) != 103 || len(sr) != 103 {
				t.Fatal("READY size")
			}
			if err = c.VerifyReady(sr); err != nil {
				t.Fatal(err)
			}
			if err = s.VerifyReady(cr); err != nil {
				t.Fatal(err)
			}
			if _, err = c.StartRecords(); !errors.Is(err, ErrNotReady) {
				t.Fatal("peer proof replaced local publication")
			}
			if err = c.MarkReadySubmitted(); err != nil {
				t.Fatal(err)
			}
			if err = s.MarkReadySubmitted(); err != nil {
				t.Fatal(err)
			}
			started, err := c.StartRecords()
			if err != nil || started != ce {
				t.Fatal(err)
			}
			defer ce.Close()
			started, err = s.StartRecords()
			if err != nil || started != se {
				t.Fatal(err)
			}
			defer se.Close()
			if _, err = c.StartRecords(); !errors.Is(err, ErrNotReady) {
				t.Fatal("root transferred twice")
			}
			for _, e := range []*Engine{ce, se} {
				if err = e.OpenScope(1); err != nil {
					t.Fatal(err)
				}
			}
			wire := sealed(t, ce, protocolv4.FrameStreamData, 1, []byte("after dual READY"))
			packet, _, _, err := se.Open(wire, acceptRecord)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			plain, err := packet.Bytes()
			if err != nil || !bytes.Equal(plain, []byte("after dual READY")) {
				t.Fatal(err)
			}
		})
	}
}
func TestHandshakeRejectsWrongPhaseAndForgedReady(t *testing.T) {
	client, server := handshakePair(t, protocolv4.DHProfileX25519)
	if _, err := server.WriteMessage(); !errors.Is(err, ErrHandshake) {
		t.Fatal("responder wrote before authenticating first message")
	}
	if _, err := server.Finish(); !errors.Is(err, ErrHandshake) {
		t.Fatal("failed owner recovered")
	}
	client.Close()
	client, server = handshakePair(t, protocolv4.DHProfileP256)
	c, s := completeNoise(t, client, server)
	config := Config{MaxFrame: 4096, MaxScopes: 4, WorkSlots: 2, Maintenance: MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}}
	if _, err := s.PrepareRecords(config); err != nil {
		t.Fatal(err)
	}
	ready, err := s.Ready()
	if err != nil {
		t.Fatal(err)
	}
	ready[len(ready)-1] ^= 1
	if err = c.VerifyReady(ready); !errors.Is(err, ErrHandshake) {
		t.Fatal("forged READY accepted")
	}
	ready[len(ready)-1] ^= 1
	if err = c.VerifyReady(ready); !errors.Is(err, ErrHandshake) {
		t.Fatal("failed READY owner recovered")
	}
}
