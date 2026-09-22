package protocolv4

// Fixed public fixtures only. This file is excluded from production builds.
// The pinned library source has an explicit public-length interface extension.
// Both profiles remain unqualified for complete production composition.
import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	noise "github.com/floegence/flowersec/flowersec-go/v5/internal/noisehandshake"
)

var errNoiseReference = errors.New("noise_reference_failed")

type noiseFixedDH struct {
	profile, name string
	publicBytes   int
	ephemeral     []byte
}

func (d *noiseFixedDH) GenerateKeypair(io.Reader) (noise.DHKey, error) {
	private := d.ephemeral
	d.ephemeral = nil // No repeated generation or ambient entropy fallback.
	defer clear(private)
	public, err := dhPublicReference(d.profile, private)
	if err != nil {
		return noise.DHKey{}, errNoiseReference
	}
	return noise.DHKey{Private: bytes.Clone(private), Public: public}, nil
}

func (d *noiseFixedDH) DH(private, public []byte) ([]byte, error) {
	// Every real es/ss/ee/se result is checked before the library can MixKey.
	return dhReference(d.profile, private, public)
}
func (*noiseFixedDH) DHLen() int         { return DHSecretBytes }
func (d *noiseFixedDH) DHPublicLen() int { return d.publicBytes }
func (d *noiseFixedDH) DHName() string   { return d.name }

type noiseNoRandom struct{}

func (noiseNoRandom) Read([]byte) (int, error) { return 0, errNoiseReference }

type noiseProfile struct {
	Name         string `json:"noise_protocol_name"`
	PublicBytes  int    `json:"dh_public_bytes"`
	SecretBytes  int    `json:"dh_secret_bytes"`
	MessageBytes int    `json:"handshake_message_bytes"`
	TagBytes     int    `json:"tag_bytes"`
}

type noiseFixedInput struct {
	profile                                 string
	initiator                               bool
	private, public, remote, ephemeral, psk []byte
	prologue, context                       []byte
}

type noiseCompletion struct {
	state    *noise.HandshakeState
	i2r, r2i *noise.CipherState
}

type noiseReference struct {
	owner         *noiseCompletion
	profile       string
	spec          noiseProfile
	context       []byte
	written, read bool
}

type noiseFinished struct{ hash, root []byte }

func newNoiseReference(input noiseFixedInput) (*noiseReference, error) {
	var profiles map[string]noiseProfile
	if err := json.Unmarshal([]byte(CryptoProfilesJSON), &profiles); err != nil {
		return nil, errNoiseReference
	}
	spec, registered := profiles[input.profile]
	curve, publicBytes, curveErr := dhReferenceCurve(input.profile)
	actual, err := dhPublicReference(input.profile, input.private)
	if !registered || curveErr != nil || err != nil || !bytes.Equal(actual, input.public) ||
		len(input.remote) != spec.PublicBytes || len(input.psk) != DHSecretBytes || len(input.context) != sha256.Size ||
		spec.PublicBytes != publicBytes || spec.SecretBytes != DHSecretBytes || spec.MessageBytes != spec.PublicBytes+spec.TagBytes {
		return nil, errNoiseReference
	}
	if _, err := curve.NewPublicKey(input.remote); err != nil {
		return nil, errNoiseReference
	}
	if _, err := dhPublicReference(input.profile, input.ephemeral); err != nil {
		return nil, errNoiseReference
	}
	dh := &noiseFixedDH{profile: input.profile, publicBytes: publicBytes, ephemeral: bytes.Clone(input.ephemeral)}
	var cipher noise.CipherFunc
	switch input.profile {
	case DHProfileX25519:
		dh.name, cipher = "25519", noise.CipherChaChaPoly
	case DHProfileP256:
		dh.name, cipher = "P256", noise.CipherAESGCM
	default:
		clear(dh.ephemeral)
		return nil, errNoiseReference
	}
	suite := noise.NewCipherSuite(dh, cipher, noise.HashSHA256)
	if spec.Name != "Noise_"+noise.HandshakeKK.Name+"psk0_"+string(suite.Name()) {
		clear(dh.ephemeral)
		return nil, errNoiseReference
	}
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite, Pattern: noise.HandshakeKK, Initiator: input.initiator,
		Random: noiseNoRandom{}, Prologue: bytes.Clone(input.prologue),
		PresharedKey: bytes.Clone(input.psk), PresharedKeyPlacement: 0,
		StaticKeypair: noise.DHKey{Private: bytes.Clone(input.private), Public: bytes.Clone(input.public)},
		PeerStatic:    bytes.Clone(input.remote),
	})
	if err != nil {
		clear(dh.ephemeral)
		return nil, errNoiseReference
	}
	return &noiseReference{owner: &noiseCompletion{state: state}, profile: input.profile, spec: spec, context: bytes.Clone(input.context)}, nil
}

func (n *noiseReference) take() *noiseCompletion {
	owner := n.owner
	n.owner = nil
	return owner
}

func (n *noiseReference) write() ([]byte, error) {
	owner := n.take()
	if owner == nil || n.written {
		return nil, errNoiseReference
	}
	message, i2r, r2i, err := owner.state.WriteMessage(nil, nil)
	if err != nil || len(message) != n.spec.MessageBytes {
		return nil, errNoiseReference
	}
	n.written = true
	owner.i2r, owner.r2i = i2r, r2i
	n.owner = owner
	return message, nil
}

func (n *noiseReference) receive(message []byte) error {
	owner := n.take()
	if owner == nil || n.read || len(message) != n.spec.MessageBytes {
		return errNoiseReference
	}
	payload, i2r, r2i, err := owner.state.ReadMessage(nil, bytes.Clone(message))
	if err != nil || len(payload) != 0 {
		return errNoiseReference
	}
	n.read = true
	owner.i2r, owner.r2i = i2r, r2i
	n.owner = owner
	return nil
}

func (n *noiseReference) finish() (*noiseFinished, error) {
	owner := n.take()
	if owner == nil || !n.written || !n.read || owner.state.MessageIndex() != 2 || owner.i2r == nil || owner.r2i == nil {
		return nil, errNoiseReference
	}
	hash := bytes.Clone(owner.state.ChannelBinding())
	if len(hash) != sha256.Size {
		return nil, errNoiseReference
	}
	// The public API prose describes send/receive; the pinned library's actual
	// Split returns canonical first/second for both roles. No transport operation
	// is ever called. Internal library copies are not claimed to be zeroized.
	i2r := owner.i2r.UnsafeKey()
	defer clear(i2r[:])
	info, err := noiseRootInfo(n.profile, hash, n.context)
	if err != nil {
		return nil, errNoiseReference
	}
	root, err := hkdf.Expand(sha256.New, i2r[:], string(info), sha256.Size)
	if err != nil {
		return nil, errNoiseReference
	}
	return &noiseFinished{hash: hash, root: root}, nil
}

func noiseRootInfo(profile string, hash, context []byte) ([]byte, error) {
	var domains []struct {
		Name  string `json:"name"`
		Label string `json:"label_bytes"`
		Input struct {
			Parts []struct{ Name, Encoding string } `json:"parts"`
		} `json:"input_schema"`
	}
	if err := json.Unmarshal([]byte(DomainRegistryJSON), &domains); err != nil {
		return nil, errNoiseReference
	}
	for _, domain := range domains {
		if domain.Name != "initial_root" {
			continue
		}
		info, err := hex.DecodeString(domain.Label)
		if err != nil {
			return nil, errNoiseReference
		}
		for _, part := range domain.Input.Parts {
			var value []byte
			switch {
			case part.Name == "profile" && part.Encoding == "lp-ascii":
				value = []byte(profile)
			case part.Name == "handshake_hash" && part.Encoding == "lp-bytes":
				value = hash
			case part.Name == "context_digest" && part.Encoding == "lp-bytes":
				value = context
			default:
				return nil, errNoiseReference
			}
			if uint64(len(value)) > uint64(^uint32(0)) {
				return nil, errNoiseReference
			}
			info = binary.BigEndian.AppendUint32(info, uint32(len(value)))
			info = append(info, value...)
		}
		return info, nil
	}
	return nil, errNoiseReference
}

type noiseTranscript struct {
	ID       string `json:"id"`
	Profile  string `json:"profile"`
	Message1 string `json:"message1_hex"`
	Message2 string `json:"message2_hex"`
	Hash     string `json:"handshake_hash_hex"`
	I2R      string `json:"split_i2r_hex"`
	R2I      string `json:"split_r2i_hex"`
	Root     string `json:"initial_root_hex"`
	Info     string `json:"initial_root_info_hex"`
}

type noiseCorpus struct {
	Schema      string            `json:"schema_sha256"`
	Inputs      map[string]string `json:"inputs"`
	Transcripts []noiseTranscript `json:"transcripts"`
	Negatives   []struct {
		ID, Transcript string
		Flight         int
		Message        string `json:"message_hex"`
		Error          string `json:"expected_error"`
	} `json:"negatives"`
}

func loadNoiseCorpus(t *testing.T) noiseCorpus {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v4/noise.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus noiseCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != SchemaSHA256 || len(corpus.Transcripts) != 2 {
		t.Fatal("Noise corpus schema/coverage drift")
	}
	return corpus
}

func noiseHex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func (c noiseCorpus) input(t *testing.T, profile string, initiator bool) noiseFixedInput {
	t.Helper()
	local, remote := "client", "server"
	if !initiator {
		local, remote = remote, local
	}
	private := noiseHex(t, c.Inputs[local+"_static_private_hex"])
	public, err := dhPublicReference(profile, private)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := dhPublicReference(profile, noiseHex(t, c.Inputs[remote+"_static_private_hex"]))
	if err != nil {
		t.Fatal(err)
	}
	return noiseFixedInput{profile: profile, initiator: initiator, private: private, public: public, remote: peer,
		ephemeral: noiseHex(t, c.Inputs[local+"_ephemeral_private_hex"]), psk: noiseHex(t, c.Inputs["psk_hex"]),
		prologue: noiseHex(t, c.Inputs["prologue_hex"]), context: noiseHex(t, c.Inputs["context_digest_hex"])}
}

func noiseAssertDead(t *testing.T, n *noiseReference) {
	t.Helper()
	if _, err := n.finish(); err != errNoiseReference {
		t.Fatal("completion recovered")
	}
	if _, err := n.write(); err != errNoiseReference {
		t.Fatal("write recovered")
	}
	if err := n.receive(nil); err != errNoiseReference {
		t.Fatal("read recovered")
	}
}

func TestV4NoiseSharedTranscripts(t *testing.T) {
	corpus := loadNoiseCorpus(t)
	covered := 0
	for _, vector := range corpus.Transcripts {
		covered++
		for _, initiator := range []bool{true, false} {
			n, err := newNoiseReference(corpus.input(t, vector.Profile, initiator))
			if err != nil {
				t.Fatal(err)
			}
			// Each role reads the independent Rust capture, not its own Go peer.
			if !initiator {
				if err := n.receive(noiseHex(t, vector.Message1)); err != nil {
					t.Fatal(err)
				}
			}
			message, err := n.write()
			want := vector.Message2
			if initiator {
				want = vector.Message1
			}
			if err != nil || hex.EncodeToString(message) != want {
				t.Fatal("independent message differs", err)
			}
			if initiator {
				if err := n.receive(noiseHex(t, vector.Message2)); err != nil {
					t.Fatal(err)
				}
			}
			i2r, r2i := n.owner.i2r.UnsafeKey(), n.owner.r2i.UnsafeKey()
			if hex.EncodeToString(i2r[:]) != vector.I2R || hex.EncodeToString(r2i[:]) != vector.R2I {
				t.Fatal("canonical Split differs")
			}
			clear(i2r[:])
			clear(r2i[:])
			info, err := noiseRootInfo(vector.Profile, noiseHex(t, vector.Hash), noiseHex(t, corpus.Inputs["context_digest_hex"]))
			if err != nil || hex.EncodeToString(info) != vector.Info {
				t.Fatal("root info differs")
			}
			finished, err := n.finish()
			if err != nil || hex.EncodeToString(finished.hash) != vector.Hash || hex.EncodeToString(finished.root) != vector.Root {
				t.Fatal("H/root differs", err)
			}
			clear(finished.root)
			noiseAssertDead(t, n)
		}
	}
	if covered != len(corpus.Transcripts) {
		t.Fatal("profile transcript missing")
	}
}

func TestV4NoiseSharedNegatives(t *testing.T) {
	corpus := loadNoiseCorpus(t)
	covered := 0
	for _, transcript := range corpus.Transcripts {
		for _, vector := range corpus.Negatives {
			if vector.Transcript != transcript.ID {
				continue
			}
			covered++
			t.Run(vector.ID, func(t *testing.T) {
				if vector.Error != errNoiseReference.Error() || (vector.Flight != 1 && vector.Flight != 2) {
					t.Fatal("bad negative fixture")
				}
				n, err := newNoiseReference(corpus.input(t, transcript.Profile, vector.Flight == 2))
				if err != nil {
					t.Fatal(err)
				}
				if vector.Flight == 2 {
					if _, err := n.write(); err != nil {
						t.Fatal(err)
					}
				}
				if err := n.receive(noiseHex(t, vector.Message)); err != errNoiseReference {
					t.Fatal("invalid message accepted", err)
				}
				noiseAssertDead(t, n)
			})
		}
	}
	if covered != len(corpus.Negatives) {
		t.Fatal("incomplete negative coverage")
	}
}

func TestV4NoiseFailureAndCompletionGuards(t *testing.T) {
	for _, profile := range []string{DHProfileX25519, DHProfileP256} {
		t.Run(profile, func(t *testing.T) { noiseFailureAndCompletionGuards(t, profile) })
	}
}

func noiseFailureAndCompletionGuards(t *testing.T, profile string) {
	corpus := loadNoiseCorpus(t)
	fresh := func(initiator bool) *noiseReference {
		t.Helper()
		n, err := newNoiseReference(corpus.input(t, profile, initiator))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, initiator := range []bool{true, false} {
		noiseAssertDead(t, fresh(initiator))
	}
	server := fresh(false)
	if _, err := server.write(); err != errNoiseReference {
		t.Fatal("wrong turn accepted")
	}
	noiseAssertDead(t, server)
	client := fresh(true)
	if err := client.receive(make([]byte, client.spec.MessageBytes)); err != errNoiseReference {
		t.Fatal("wrong turn accepted")
	}
	noiseAssertDead(t, client)
	client, server = fresh(true), fresh(false)
	first, err := client.write()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.write(); err != errNoiseReference {
		t.Fatal("duplicate write accepted")
	}
	noiseAssertDead(t, client)
	if err := server.receive(first); err != nil {
		t.Fatal(err)
	}
	if err := server.receive(first); err != errNoiseReference {
		t.Fatal("duplicate read accepted")
	}
	noiseAssertDead(t, server)
	client, server = fresh(true), fresh(false)
	first, err = client.write()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.receive(first); err != nil {
		t.Fatal(err)
	}
	noiseAssertDead(t, client)
	noiseAssertDead(t, server)

	for _, mutation := range []func(*noiseFixedInput){
		func(i *noiseFixedInput) { i.psk[0] ^= 1 },
		func(i *noiseFixedInput) { i.prologue[0] ^= 1 },
		func(i *noiseFixedInput) { i.remote = bytes.Clone(i.public) },
	} {
		input := corpus.input(t, profile, false)
		mutation(&input)
		server, err := newNoiseReference(input)
		if err != nil {
			t.Fatal(err)
		}
		client := fresh(true)
		first, err := client.write()
		if err != nil {
			t.Fatal(err)
		}
		if err := server.receive(first); err != errNoiseReference {
			t.Fatal("binding mismatch accepted")
		}
		noiseAssertDead(t, server)
	}
	input := corpus.input(t, profile, true)
	if profile == DHProfileX25519 {
		input.remote = make([]byte, DHX25519PublicBytes)
	} else {
		// An accepted on-curve point whose real es result is zero for scalar1.
		raw, err := os.ReadFile("../../../testdata/transport_v4/profile_dh.json")
		if err != nil {
			t.Fatal(err)
		}
		var dhCorpus struct {
			Vectors []struct {
				ID      string
				Private string `json:"private_hex"`
				Public  string `json:"public_hex"`
			}
		}
		if err := json.Unmarshal(raw, &dhCorpus); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, vector := range dhCorpus.Vectors {
			if vector.ID == "dh_p_zero_result" {
				input.ephemeral, input.remote = noiseHex(t, vector.Private), noiseHex(t, vector.Public)
				found = true
			}
		}
		if !found {
			t.Fatal("missing P256 zero-result fixture")
		}
	}
	client, err = newNoiseReference(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.write(); err != errNoiseReference {
		t.Fatal("zero DH accepted")
	}
	noiseAssertDead(t, client)
}

func TestV4NoiseMaterialAndSnapshotBoundaries(t *testing.T) {
	for _, profile := range []string{DHProfileX25519, DHProfileP256} {
		t.Run(profile, func(t *testing.T) { noiseMaterialAndSnapshotBoundaries(t, profile) })
	}
}

func noiseMaterialAndSnapshotBoundaries(t *testing.T, profile string) {
	corpus := loadNoiseCorpus(t)
	other := DHProfileP256
	if profile == DHProfileP256 {
		other = DHProfileX25519
	}
	for _, mutation := range []func(*noiseFixedInput){
		func(i *noiseFixedInput) { i.profile = other },
		func(i *noiseFixedInput) { i.profile = "unregistered" },
		func(i *noiseFixedInput) { i.public = bytes.Clone(i.remote) },
		func(i *noiseFixedInput) { i.private = i.private[:31] },
		func(i *noiseFixedInput) { i.ephemeral = append(i.ephemeral, 0) },
		func(i *noiseFixedInput) { i.remote = i.remote[:31] },
		func(i *noiseFixedInput) { i.remote = append(i.remote, 0) },
		func(i *noiseFixedInput) { i.psk = nil },
		func(i *noiseFixedInput) { i.context = nil },
	} {
		input := corpus.input(t, profile, true)
		mutation(&input)
		if _, err := newNoiseReference(input); err != errNoiseReference {
			t.Fatal("invalid material accepted")
		}
	}
	input := corpus.input(t, profile, true)
	client, err := newNoiseReference(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, bytes := range [][]byte{input.private, input.public, input.remote, input.ephemeral, input.psk, input.prologue, input.context} {
		clear(bytes)
	}
	for _, vector := range corpus.Transcripts {
		if vector.Profile != profile {
			continue
		}
		first, err := client.write()
		if err != nil || hex.EncodeToString(first) != vector.Message1 {
			t.Fatal("caller alias changed message")
		}
		second := noiseHex(t, vector.Message2)
		if err := client.receive(second); err != nil {
			t.Fatal(err)
		}
		clear(second)
		finished, err := client.finish()
		if err != nil || hex.EncodeToString(finished.root) != vector.Root {
			t.Fatal("caller alias changed completion")
		}
		clear(finished.root)
	}
}
