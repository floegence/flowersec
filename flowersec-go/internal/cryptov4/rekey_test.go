package cryptov4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func roundDecoder(t *testing.T, e *Engine) func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) (*protocolv4.Frame, error) {
	t.Helper()
	d, err := protocolv4.NewRecordDecoder(int(e.config.MaxFrame), 8192)
	if err != nil {
		t.Fatal(err)
	}
	return func(kind protocolv4.FrameType, header protocolv4.RecordHeader, plain []byte) (*protocolv4.Frame, error) {
		return d.DecodeRecordBody(plain, kind, header, 1-e.config.SendDirection, protocolv4.DecodeContext{Selectors: map[string]string{"crypto_profile_id": e.config.Profile}})
	}
}

func roundPhase(t *testing.T, from, to *Engine, plain []byte) *protocolv4.Frame {
	t.Helper()
	wire := sealed(t, from, protocolv4.FrameRekey, 0, plain)
	decode := roundDecoder(t, to)
	var body *protocolv4.Frame
	packet, _, _, err := to.Open(wire, func(kind protocolv4.FrameType, h protocolv4.RecordHeader, p []byte) error {
		var err error
		body, err = decode(kind, h, p)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	packet.Release()
	return body
}

type roundPair struct {
	client, server *Engine
	c, s           *RekeyRound
	cf, sf         *ApplicationFreeze
	now            *time.Time
}

func TestRekeyMarkerCapacityRefusalKeepsOriginalRound(t *testing.T) {
	pair := preparedRound(t, protocolv4.DHProfileX25519)
	marker, err := pair.c.SealMarker()
	if err != nil {
		t.Fatal(err)
	}
	defer marker.Release()
	wire, err := marker.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	e := pair.server
	e.mu.Lock()
	w, err := e.workspace(true, protocolv4.ClientToServer)
	e.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	decode := roundDecoder(t, e)
	before := e.counts[protocolv4.ClientToServer]
	if _, _, err := e.OpenRekeyMarker(wire, decode); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if pair.s.closed || e.rekey != pair.s || pair.s.state != 2 || e.counts[protocolv4.ClientToServer] != before {
		t.Fatal("no-attempt refusal destroyed the round or consumed usage")
	}
	e.release(w)
	packet, body, err := e.OpenRekeyMarker(wire, decode)
	if err != nil {
		t.Fatal("original candidate failed after capacity returned", err)
	}
	body.Release()
	packet.Release()
}

func TestRekeyUnattemptedExitCompletesConcurrentClose(t *testing.T) {
	pair := preparedRound(t, protocolv4.DHProfileX25519)
	r := pair.s
	if err := r.begin(); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if err := r.endUnattempted(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if pair.server.rekey != nil || r.secret != [32]byte{} || r.root != [32]byte{} || r.ephemeral != nil {
		t.Fatal("closed capacity-refused round retained original secrets")
	}
}

func preparedRound(t *testing.T, profile string) roundPair {
	t.Helper()
	client, server, now := enginePair(t, profile)
	c, err := client.BeginRekey(uint64(now.Add(time.Minute).UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.BeginRekey(uint64(now.Add(time.Minute).UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.PrepareInit(); err != nil {
		t.Fatal(err)
	}
	cf, _, err := client.FreezeApplication(make([]protocolv4.RecordHeader, 4))
	if err != nil {
		t.Fatal(err)
	}
	init, err := c.BuildInit(make([]byte, 4096), []protocolv4.RecordHeader{{Scope: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err = cf.Commit(); err != nil {
		t.Fatal(err)
	}
	body := roundPhase(t, client, server, init)
	if err = s.AcceptInit(body); err != nil {
		t.Fatal(err)
	}
	body.Release()
	sf, _, err := server.FreezeApplication(make([]protocolv4.RecordHeader, 4))
	if err != nil {
		t.Fatal(err)
	}
	if err = sf.Commit(); err != nil {
		t.Fatal(err)
	}
	reply, err := s.BuildReply(make([]byte, 4096), []protocolv4.RecordHeader{{Scope: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.InstallCandidate(); err != nil {
		t.Fatal(err)
	}
	body = roundPhase(t, server, client, reply)
	if err = s.ArmMarker(); err != nil {
		t.Fatal(err)
	}
	if err = c.AcceptReply(body); err != nil {
		t.Fatal(err)
	}
	body.Release()
	if c.root != s.root || c.transcript != s.transcript || c.root == client.current.root {
		t.Fatal("candidate mismatch")
	}
	if err = c.InstallCandidate(); err != nil {
		t.Fatal(err)
	}
	if err = c.ArmMarker(); err != nil {
		t.Fatal(err)
	}
	return roundPair{client, server, c, s, cf, sf, now}
}

func roundMarker(t *testing.T, from *RekeyRound, to *Engine) []byte {
	t.Helper()
	packet, err := from.SealMarker()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := packet.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wire = bytes.Clone(wire)
	packet.Release()
	p, body, err := to.OpenRekeyMarker(wire, roundDecoder(t, to))
	if err != nil {
		t.Fatal(err)
	}
	body.Release()
	p.Release()
	return wire
}

func TestRekeyRealDirectionalMarkers(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			p := preparedRound(t, profile)
			oldServer := sealed(t, p.server, protocolv4.FramePing, 0, []byte("old tail"))
			commit := roundMarker(t, p.c, p.server)
			_, header, _, err := protocolv4.ParseRecord(commit, profile, p.client.config.MaxFrame)
			if err != nil || header != (protocolv4.RecordHeader{Epoch: 1}) {
				t.Fatal(header, err)
			}
			if _, err = p.client.Seal(protocolv4.FrameStreamData, 1, []byte("still frozen")); !errors.Is(err, ErrTransition) {
				t.Fatal(err)
			}
			newControl := sealed(t, p.client, protocolv4.FramePong, 0, []byte("new maintenance"))
			packet, _, header, err := p.server.Open(newControl, acceptRecord)
			if err != nil || header.Epoch != 1 || header.Sequence != 1 {
				t.Fatal(header, err)
			}
			packet.Release()
			packet, _, header, err = p.client.Open(oldServer, acceptRecord)
			if err != nil || header.Epoch != 0 {
				t.Fatal(header, err)
			}
			packet.Release()
			ack, err := p.s.SealMarker()
			if err != nil {
				t.Fatal(err)
			}
			if err = p.s.Complete(); err != nil {
				t.Fatal(err)
			}
			if err = p.sf.Resume(); err != nil {
				t.Fatal(err)
			}
			ackWire, err := ack.Bytes()
			if err != nil {
				t.Fatal("ACK lost after local completion", err)
			}
			ackWire = bytes.Clone(ackWire)
			ack.Release()
			// The server may publish new application input before ACK reaches client.
			early := sealed(t, p.server, protocolv4.FrameStreamData, 1, []byte("private until ACK"))
			packet, _, _, err = p.client.Open(early, acceptRecord)
			if err != nil {
				t.Fatal(err)
			}
			packet.Release()
			if err = p.client.ApplicationReady(); !errors.Is(err, ErrTransition) {
				t.Fatal("early data completed rekey", err)
			}
			packet, body, err := p.client.OpenRekeyMarker(ackWire, roundDecoder(t, p.client))
			if err != nil {
				t.Fatal(err)
			}
			packet.Release()
			body.Release()
			if err = p.c.Complete(); err != nil {
				t.Fatal(err)
			}
			if err = p.cf.Resume(); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err = p.client.Open(oldServer, acceptRecord); !errors.Is(err, ErrEpoch) {
				t.Fatal("old gate reopened", err)
			}
			if _, _, err = p.client.OpenRekeyMarker(ackWire, roundDecoder(t, p.client)); !errors.Is(err, ErrTransition) {
				t.Fatal("ACK reused", err)
			}
			newData := sealed(t, p.client, protocolv4.FrameStreamData, 1, []byte("resumed"))
			packet, _, _, err = p.server.Open(newData, acceptRecord)
			if err != nil {
				t.Fatal(err)
			}
			packet.Release()
		})
	}
}

func TestRekeyMarkerRejectsDeletedOldSuffix(t *testing.T) {
	p := preparedRound(t, protocolv4.DHProfileX25519)
	_ = sealed(t, p.client, protocolv4.FramePing, 0, []byte("removed by relay"))
	packet, err := p.c.SealMarker()
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	wire, err := packet.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = p.server.OpenRekeyMarker(wire, roundDecoder(t, p.server)); !errors.Is(err, ErrRekey) {
		t.Fatal("missing old suffix accepted", err)
	}
	if p.server.switching.received {
		t.Fatal("failed marker opened new gate")
	}
}

func TestRekeyMarkerRejectsInnerMACAndTranscript(t *testing.T) {
	for _, mutation := range []string{"mac", "transcript"} {
		t.Run(mutation, func(t *testing.T) {
			p := preparedRound(t, protocolv4.DHProfileP256)
			if mutation == "mac" {
				p.c.root[0] ^= 1
			} else {
				p.c.transcript[0] ^= 1
			}
			packet, err := p.c.SealMarker()
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			wire, err := packet.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = p.server.OpenRekeyMarker(wire, roundDecoder(t, p.server)); !errors.Is(err, ErrRekey) {
				t.Fatal("inner binding not verified", err)
			}
		})
	}
}

func TestRekeyMarkerPublicationAndDeadline(t *testing.T) {
	p := preparedRound(t, protocolv4.DHProfileX25519)
	packet, err := p.client.Seal(protocolv4.FramePing, 0, []byte("original provider owns tail"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.c.SealMarker(); !errors.Is(err, ErrTransition) {
		t.Fatal("marker overtook live tail", err)
	}
	packet.Release()
	q := preparedRound(t, protocolv4.DHProfileP256)
	*q.now = q.now.Add(time.Minute)
	if _, err = q.c.SealMarker(); !errors.Is(err, ErrExpired) {
		t.Fatal("deadline refreshed", err)
	}
}

func TestRekeyProductionSharedCorpus(t *testing.T) {
	var corpus struct {
		Schema string `json:"schema_sha256"`
		Rounds []struct {
			ID      string
			Context struct {
				Profile string
				Epoch   uint32
				Hash    string `json:"handshake_hash_hex"`
				Digest  string `json:"context_digest_hex"`
				ID      string `json:"rekey_id_hex"`
			}
			Old        string `json:"old_root_hex"`
			New        string `json:"new_root_hex"`
			Secret     string `json:"secret_hex"`
			Transcript string `json:"transcript_hex"`
			InitDigest string `json:"init_digest_hex"`
			Input      struct {
				Private string `json:"client_private_hex"`
			}
			Phases []struct {
				Schema   string
				Message  string `json:"message_hex"`
				Unsigned string `json:"unsigned_hex"`
				MAC      string `json:"confirmation_mac_hex"`
			}
		}
	}
	raw, err := os.ReadFile("../../../testdata/transport_v4/rekey.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != protocolv4.SchemaSHA256 || len(corpus.Rounds) != 4 {
		t.Fatal("corpus binding")
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, fixture := range corpus.Rounds {
		t.Run(fixture.ID, func(t *testing.T) {
			e, _, now := enginePair(t, fixture.Context.Profile)
			copy(e.current.root[:], unhex(fixture.Old))
			e.current.number = fixture.Context.Epoch
			copy(e.config.HandshakeHash[:], unhex(fixture.Context.Hash))
			copy(e.config.ContextDigest[:], unhex(fixture.Context.Digest))
			r, err := e.BeginRekey(uint64(now.Add(time.Minute).UnixMilli()))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			copy(r.id[:], unhex(fixture.Context.ID))
			if !bytes.Equal(r.secret[:], unhex(fixture.Secret)) {
				t.Fatal("secret")
			}
			for i, phase := range fixture.Phases {
				d, err := protocolv4.NewRecordDecoder(4096, 8192)
				if err != nil {
					t.Fatal(err)
				}
				n, role, err := protocolv4.RekeyPhaseInfo(phase.Schema)
				if err != nil {
					t.Fatal(err)
				}
				h := protocolv4.RecordHeader{Epoch: fixture.Context.Epoch}
				if n >= 3 {
					h.Epoch++
				}
				body, err := d.DecodeRecordBody(unhex(phase.Message), protocolv4.FrameRekey, h, role, protocolv4.DecodeContext{Selectors: map[string]string{"crypto_profile_id": fixture.Context.Profile}})
				if err != nil {
					t.Fatal(err)
				}
				unsigned, err := body.CopyMACProjection(r.scratch)
				if err != nil || !bytes.Equal(unsigned, unhex(phase.Unsigned)) {
					t.Fatal("projection", err)
				}
				mac, err := r.mac(phase.Schema, unsigned)
				if err != nil || !bytes.Equal(mac, unhex(phase.MAC)) {
					t.Fatal("MAC", err)
				}
				if err = r.verify(body, phase.Schema); err != nil {
					t.Fatal("verify", err)
				}
				if i == 0 {
					r.initSize = copy(r.init, body.Document.Bytes())
					if err = r.digestInit(); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(r.initDigest[:], unhex(fixture.InitDigest)) {
						t.Fatal("INIT digest")
					}
				}
				if i == 1 {
					r.replySize = copy(r.reply, body.Document.Bytes())
					peer, _ := body.Field("server_ephemeral").ByteString()
					r.peerPublic = bytes.Clone(peer)
					curve, _ := profileCurve(fixture.Context.Profile)
					key, err := curve.NewPrivateKey(unhex(fixture.Input.Private))
					if err != nil {
						t.Fatal(err)
					}
					r.ephemeral = &DHKey{key: key}
					if err = r.deriveCandidate(); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(r.root[:], unhex(fixture.New)) || !bytes.Equal(r.transcript[:], unhex(fixture.Transcript)) {
						t.Fatal("candidate / transcript")
					}
				}
				body.Release()
			}
		})
	}
}
