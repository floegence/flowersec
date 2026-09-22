package cryptov4

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	noise "github.com/floegence/flowersec/flowersec-go/v5/internal/noisehandshake"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrHandshake = errors.New("cryptov4: handshake failed")

// StaticDH and IdentitySigner are narrow internal key capabilities. Neither
// interface exports private keys; the handshake owns their bounded invocation.
type StaticDH interface {
	PublicKey() []byte
	SharedSecret([]byte) ([]byte, error)
}
type IdentitySigner interface {
	PublicKey() []byte
	Sign([]byte) ([]byte, error)
}

type DHKey struct {
	mu  sync.Mutex
	key *ecdh.PrivateKey
}

func GenerateDHKey(profile string) (*DHKey, error) {
	curve, err := profileCurve(profile)
	if err != nil {
		return nil, err
	}
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DHKey{key: key}, nil
}
func profileCurve(profile string) (ecdh.Curve, error) {
	switch profile {
	case protocolv4.DHProfileX25519:
		return ecdh.X25519(), nil
	case protocolv4.DHProfileP256:
		return ecdh.P256(), nil
	}
	return nil, protocolv4.ErrRecordProfile
}
func (k *DHKey) PublicKey() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key == nil {
		return nil
	}
	return k.key.PublicKey().Bytes()
}
func (k *DHKey) SharedSecret(remote []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key == nil {
		return nil, ErrClosed
	}
	peer, err := k.key.Curve().NewPublicKey(remote)
	if err != nil {
		return nil, ErrHandshake
	}
	secret, err := k.key.ECDH(peer)
	if err != nil || len(secret) != 32 || bytes.Equal(secret, make([]byte, 32)) {
		clear(secret)
		return nil, ErrHandshake
	}
	return secret, nil
}
func (k *DHKey) Close() { k.mu.Lock(); k.key = nil; k.mu.Unlock() }

// The pinned Noise adapter carries one-byte capability selectors, never static
// private bytes. Only the adapter sees DH output and its private ephemeral key.
type handshakeDH struct {
	profile, name string
	publicBytes   int
	static        StaticDH
	ephemeral     *DHKey
}

func (d *handshakeDH) GenerateKeypair(random io.Reader) (noise.DHKey, error) {
	if d.ephemeral != nil {
		return noise.DHKey{}, ErrHandshake
	}
	curve, err := profileCurve(d.profile)
	if err != nil {
		return noise.DHKey{}, err
	}
	key, err := curve.GenerateKey(random)
	if err != nil {
		return noise.DHKey{}, err
	}
	d.ephemeral = &DHKey{key: key}
	return noise.DHKey{Private: []byte{1}, Public: d.ephemeral.PublicKey()}, nil
}
func (d *handshakeDH) DH(private, remote []byte) ([]byte, error) {
	if len(private) != 1 || len(remote) != d.publicBytes {
		return nil, ErrHandshake
	}
	var key StaticDH
	switch private[0] {
	case 0:
		key = d.static
	case 1:
		if d.ephemeral == nil {
			return nil, ErrHandshake
		}
		key = d.ephemeral
	default:
		return nil, ErrHandshake
	}
	// The original encoded public key reaches Noise unchanged. X25519 masking
	// and reduction occur only inside the RFC 7748 library DH operation.
	secret, err := key.SharedSecret(remote)
	if err != nil || len(secret) != 32 || bytes.Equal(secret, make([]byte, 32)) {
		clear(secret)
		return nil, ErrHandshake
	}
	return secret, nil
}
func (*handshakeDH) DHLen() int         { return 32 }
func (d *handshakeDH) DHPublicLen() int { return d.publicBytes }
func (d *handshakeDH) DHName() string   { return d.name }
func (d *handshakeDH) close() {
	if d.ephemeral != nil {
		d.ephemeral.Close()
		d.ephemeral = nil
	}
	d.static = nil
}

// HandshakeConfig is created only after independent admission/certificate and
// actual carrier-context validation. This layer never obtains trust from Noise.
type HandshakeConfig struct {
	Profile                                       string
	Session                                       protocolv4.ArtifactSessionParameters
	Role                                          protocolv4.Direction
	PSK                                           [32]byte
	FSB, FSA                                      []byte
	ContextDigest, AdmissionBinding               [32]byte
	LocalCertificateDigest, PeerCertificateDigest [32]byte
	LocalDHPublic, PeerDHPublic                   []byte
	LocalEdPublic, PeerEdPublic                   [32]byte
	LocalDH                                       StaticDH
	Signer                                        IdentitySigner
	Features                                      uint64
	Deadline                                      *timev4.Deadline
	SessionDeadlineMS                             uint64
	Authorization                                 protocolv4.AuthorizationGuard
	Clock                                         *timev4.Clock
	LocalIdleDurationMS                           uint64
}
type Handshake struct {
	mu                   sync.Mutex
	closed               atomic.Bool
	config               HandshakeConfig
	state                *noise.HandshakeState
	dh                   *handshakeDH
	i2r, r2i             *noise.CipherState
	messageBytes         int
	written, read        bool
	fsbDigest, fsaDigest [32]byte
}

func NewHandshake(config HandshakeConfig) (*Handshake, error) {
	defer clear(config.PSK[:])
	if !config.Session.Contract.Valid() || config.Session.Profile != config.Profile || config.Session.IssuedAtMS >= config.Session.SessionNotAfterMS || config.SessionDeadlineMS > config.Session.SessionNotAfterMS {
		return nil, ErrConfiguration
	}
	if _, _, err := protocolv4.Bootstrap(config.Session.Contract.Limits().ApplicationProfile); err != nil {
		return nil, err
	}
	if config.Role > protocolv4.ServerToClient || config.LocalDH == nil || config.Signer == nil || config.Clock == nil || config.Authorization == nil || !config.Deadline.BelongsTo(config.Clock) || config.SessionDeadlineMS == 0 || config.Deadline.Cap() > config.SessionDeadlineMS || config.Deadline.Check() != nil {
		return nil, ErrHandshake
	}
	if err := config.Authorization.Check(); err != nil {
		return nil, err
	}
	curve, err := profileCurve(config.Profile)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(config.LocalDH.PublicKey(), config.LocalDHPublic) || !bytes.Equal(config.Signer.PublicKey(), config.LocalEdPublic[:]) {
		return nil, ErrHandshake
	}
	if _, err = curve.NewPublicKey(config.LocalDHPublic); err != nil {
		return nil, ErrHandshake
	}
	if _, err = curve.NewPublicKey(config.PeerDHPublic); err != nil {
		return nil, ErrHandshake
	}
	var profiles map[string]struct {
		Name    string `json:"noise_protocol_name"`
		Public  int    `json:"dh_public_bytes"`
		Message int    `json:"handshake_message_bytes"`
	}
	if json.Unmarshal([]byte(protocolv4.CryptoProfilesJSON), &profiles) != nil {
		return nil, ErrConfiguration
	}
	spec, ok := profiles[config.Profile]
	if !ok {
		return nil, ErrHandshake
	}
	// This validates profile/feature fields before any Noise work or signing.
	if _, err = encodeReadyMap("ReadyMACInput", map[string][]byte{"crypto_profile_id": []byte(config.Profile), "handshake_hash": make([]byte, 32), "fsb_digest": make([]byte, 32), "fsa_digest": make([]byte, 32), "transport_context_digest": config.ContextDigest[:], "admission_binding": config.AdmissionBinding[:], "certificate_digest": config.LocalCertificateDigest[:], "identity_proof": make([]byte, 64)}, map[string]uint64{"role": uint64(config.Role), "selected_features": config.Features}); err != nil {
		return nil, err
	}
	prologue, err := cryptoInput("noise_prologue", map[string][]byte{"profile": []byte(config.Profile), "context_digest": config.ContextDigest[:], "fsb": config.FSB, "fsa": config.FSA}, nil)
	if err != nil {
		return nil, err
	}
	fsb, err := cryptoInput("fsb_digest", map[string][]byte{"fsb": config.FSB}, nil)
	if err != nil {
		return nil, err
	}
	fsa, err := cryptoInput("fsa_digest", map[string][]byte{"fsa": config.FSA}, nil)
	if err != nil {
		return nil, err
	}
	dh := &handshakeDH{profile: config.Profile, publicBytes: spec.Public, static: config.LocalDH}
	var cipher noise.CipherFunc
	switch config.Profile {
	case protocolv4.DHProfileX25519:
		dh.name = "25519"
		cipher = noise.CipherChaChaPoly
	case protocolv4.DHProfileP256:
		dh.name = "P256"
		cipher = noise.CipherAESGCM
	}
	suite := noise.NewCipherSuite(dh, cipher, noise.HashSHA256)
	if spec.Name != "Noise_"+noise.HandshakeKK.Name+"psk0_"+string(suite.Name()) {
		return nil, ErrConfiguration
	}
	state, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeKK, Initiator: config.Role == protocolv4.ClientToServer, Random: rand.Reader,
		Prologue: prologue, PresharedKey: config.PSK[:], PresharedKeyPlacement: 0, StaticKeypair: noise.DHKey{Private: []byte{0}, Public: bytes.Clone(config.LocalDHPublic)}, PeerStatic: bytes.Clone(config.PeerDHPublic)})
	if err != nil {
		dh.close()
		return nil, ErrHandshake
	}
	clear(config.PSK[:])
	config.FSB = nil
	config.FSA = nil
	config.LocalDHPublic = nil
	config.PeerDHPublic = nil
	return &Handshake{config: config, state: state, dh: dh, messageBytes: spec.Message, fsbDigest: sha256.Sum256(fsb), fsaDigest: sha256.Sum256(fsa)}, nil
}
func (h *Handshake) valid() bool {
	return !h.closed.Load() && h.state != nil && h.config.Deadline.Check() == nil && h.config.Authorization.Check() == nil
}
func (h *Handshake) cleanup() {
	h.state = nil
	h.i2r = nil
	h.r2i = nil
	if h.dh != nil {
		h.dh.close()
		h.dh = nil
	}
	h.config.LocalDH = nil
	h.config.Signer = nil
}
func (h *Handshake) Close() {
	h.closed.Store(true)
	if h.mu.TryLock() {
		h.cleanup()
		h.mu.Unlock()
	}
}
func (h *Handshake) WriteMessage() ([]byte, error) {
	if !h.mu.TryLock() {
		return nil, ErrCapacity
	}
	defer h.mu.Unlock()
	if !h.valid() || h.written {
		h.closed.Store(true)
		h.cleanup()
		return nil, ErrHandshake
	}
	message, i2r, r2i, err := h.state.WriteMessage(nil, nil)
	if err != nil || len(message) != h.messageBytes || !h.valid() {
		h.closed.Store(true)
		h.cleanup()
		return nil, ErrHandshake
	}
	h.written = true
	h.i2r = i2r
	h.r2i = r2i
	return message, nil
}
func (h *Handshake) ReadMessage(message []byte) error {
	if !h.mu.TryLock() {
		return ErrCapacity
	}
	defer h.mu.Unlock()
	if !h.valid() || h.read || len(message) != h.messageBytes {
		h.closed.Store(true)
		h.cleanup()
		return ErrHandshake
	}
	payload, i2r, r2i, err := h.state.ReadMessage(nil, bytes.Clone(message))
	if err != nil || len(payload) != 0 || !h.valid() {
		clear(payload)
		h.closed.Store(true)
		h.cleanup()
		return ErrHandshake
	}
	h.read = true
	h.i2r = i2r
	h.r2i = r2i
	return nil
}

type FinishedHandshake struct {
	mu                                                  sync.Mutex
	closed                                              atomic.Bool
	config                                              HandshakeConfig
	root, hash, fsbDigest, fsaDigest                    [32]byte
	born                                                timev4.Sample
	records                                             *Engine
	localSigned, localSubmitted, peerSeen, peerVerified bool
}

// Finish consumes the one completion capability. Neither Noise Split key is
// used for transport, and the root remains confined to this crypto package.
func (h *Handshake) Finish() (*FinishedHandshake, error) {
	if !h.mu.TryLock() {
		return nil, ErrCapacity
	}
	defer h.mu.Unlock()
	defer func() { h.closed.Store(true); h.cleanup() }()
	if !h.valid() || !h.written || !h.read || h.state.MessageIndex() != 2 || h.i2r == nil || h.r2i == nil {
		return nil, ErrHandshake
	}
	var hash [32]byte
	if len(h.state.ChannelBinding()) != len(hash) {
		return nil, ErrHandshake
	}
	copy(hash[:], h.state.ChannelBinding())
	info, err := cryptoInput("initial_root", map[string][]byte{"profile": []byte(h.config.Profile), "handshake_hash": hash[:], "context_digest": h.config.ContextDigest[:]}, nil)
	if err != nil {
		return nil, err
	}
	split := h.i2r.UnsafeKey()
	defer clear(split[:])
	born, err := h.config.Deadline.Sample()
	if err != nil {
		return nil, securityTimeError(err)
	}
	root, err := hkdf.Expand(sha256.New, split[:], string(info), 32)
	if err != nil {
		return nil, ErrHandshake
	}
	defer clear(root)
	if !h.valid() {
		return nil, ErrHandshake
	}
	finished := &FinishedHandshake{config: h.config, hash: hash, fsbDigest: h.fsbDigest, fsaDigest: h.fsaDigest, born: born}
	copy(finished.root[:], root)
	finished.config.LocalDH = nil
	return finished, nil
}
func (f *FinishedHandshake) Hash() [32]byte { return f.hash }
func (f *FinishedHandshake) live() bool {
	return !f.closed.Load() && f.config.Deadline.Check() == nil && f.config.Authorization.Check() == nil
}
func (f *FinishedHandshake) cleanup() {
	clear(f.root[:])
	f.config.Signer = nil
	if f.records != nil {
		f.records.Close()
		f.records = nil
	}
}
func (f *FinishedHandshake) Close() {
	f.closed.Store(true)
	if f.mu.TryLock() {
		f.cleanup()
		f.mu.Unlock()
	}
}
func (f *FinishedHandshake) readyInputs(role protocolv4.Direction, proof []byte) (signInput, macInput, key []byte, err error) {
	certificate := f.config.LocalCertificateDigest
	if role != f.config.Role {
		certificate = f.config.PeerCertificateDigest
	}
	values := map[string][]byte{"crypto_profile_id": []byte(f.config.Profile), "handshake_hash": f.hash[:], "fsb_digest": f.fsbDigest[:], "fsa_digest": f.fsaDigest[:], "transport_context_digest": f.config.ContextDigest[:], "admission_binding": f.config.AdmissionBinding[:], "certificate_digest": certificate[:]}
	numbers := map[string]uint64{"role": uint64(role), "selected_features": f.config.Features}
	unsigned, err := encodeReadyMap("ReadyProofInput", values, numbers)
	if err != nil {
		return nil, nil, nil, err
	}
	signInput, err = cryptoInput("ready_identity", map[string][]byte{"proof": unsigned}, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	if proof == nil {
		return signInput, nil, nil, nil
	}
	values["identity_proof"] = proof
	encoded, err := encodeReadyMap("ReadyMACInput", values, numbers)
	if err != nil {
		return nil, nil, nil, err
	}
	macInput, err = cryptoInput("ready_mac", map[string][]byte{"mac_input": encoded}, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	info, err := cryptoInput("ready_key", map[string][]byte{"profile": []byte(f.config.Profile), "handshake_hash": f.hash[:], "context_digest": f.config.ContextDigest[:]}, map[string]uint64{"role": uint64(role)})
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = hkdf.Expand(sha256.New, f.root[:], string(info), 32)
	return signInput, macInput, key, err
}
func (f *FinishedHandshake) Ready() ([]byte, error) {
	if !f.mu.TryLock() {
		return nil, ErrCapacity
	}
	defer f.mu.Unlock()
	if !f.live() || f.localSigned {
		return nil, ErrHandshake
	}
	if f.records == nil {
		return nil, ErrNotReady
	}
	f.records.mu.Lock()
	readyErr := f.records.initialLive(f)
	if readyErr == nil && f.records.bootstrapEnabled && !f.records.bootstrapReserved {
		readyErr = ErrNotReady
	}
	if readyErr == nil {
		f.records.initialSigning = true
	}
	f.records.mu.Unlock()
	if readyErr != nil {
		return nil, readyErr
	}
	f.localSigned = true
	signInput, _, _, err := f.readyInputs(f.config.Role, nil)
	if err != nil {
		f.closed.Store(true)
		f.cleanup()
		return nil, err
	}
	proof, err := f.config.Signer.Sign(signInput)
	if err != nil || !protocolv4.VerifyEd25519(proof, signInput, f.config.LocalEdPublic[:]) || !f.live() {
		f.closed.Store(true)
		f.cleanup()
		return nil, ErrHandshake
	}
	_, macInput, key, err := f.readyInputs(f.config.Role, proof)
	if err != nil {
		f.closed.Store(true)
		f.cleanup()
		return nil, err
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write(macInput)
	if !f.live() {
		f.cleanup()
		return nil, ErrHandshake
	}
	ready, err := encodeReadyMap("READY", map[string][]byte{"identity_proof": proof, "confirmation_mac": mac.Sum(nil)}, nil)
	if err == nil {
		// The prepared record owner can close independently while the signer
		// runs. Its original gate must still authorize this READY result.
		f.records.mu.Lock()
		err = f.records.initialLive(f)
		f.records.mu.Unlock()
	}
	if err != nil {
		f.closed.Store(true)
		f.cleanup()
		return nil, ErrHandshake
	}
	return ready, nil
}
func (f *FinishedHandshake) VerifyReady(wire []byte) error {
	if !f.mu.TryLock() {
		return ErrCapacity
	}
	defer f.mu.Unlock()
	if !f.live() || f.peerSeen {
		return ErrHandshake
	}
	f.peerSeen = true
	proof, mac, err := decodeReady(wire)
	if err == nil {
		var signInput, macInput, key []byte
		signInput, macInput, key, err = f.readyInputs(1-f.config.Role, proof[:])
		defer clear(key)
		if err == nil {
			expected := hmac.New(sha256.New, key)
			expected.Write(macInput)
			if !hmac.Equal(expected.Sum(nil), mac[:]) || !protocolv4.VerifyEd25519(proof[:], signInput, f.config.PeerEdPublic[:]) {
				err = ErrHandshake
			}
		}
	}
	if err != nil || !f.live() {
		f.closed.Store(true)
		f.cleanup()
		return ErrHandshake
	}
	f.peerVerified = true
	return nil
}
func (f *FinishedHandshake) MarkReadySubmitted() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.live() || f.records == nil || !f.localSigned || f.localSubmitted {
		return ErrHandshake
	}
	f.records.mu.Lock()
	defer f.records.mu.Unlock()
	if err := f.records.initialLive(f); err != nil {
		return err
	}
	f.localSubmitted = true
	f.records.initialSubmitted = true
	return nil
}

// PrepareRecords creates the single private record owner before signing or
// submitting READY. It reserves its actual bounded crypto/codec workspaces;
// Session application/profile reservations are attached before Ready as well.
// Neither send nor application delivery is enabled by this preparation.
func (f *FinishedHandshake) PrepareRecords(config Config) (*Engine, error) {
	return f.prepareRecords(config, NewEngine)
}

// PrepareReservedRecords binds the original private READY/record owner to the
// Session's preadmitted Engine charge and the same shared Environment owner.
func (f *FinishedHandshake) PrepareReservedRecords(config Config, options EngineResourceOptions, reservation, environment resourcev4.Reference) (*Engine, error) {
	return f.prepareRecords(config, func(config Config) (*Engine, error) {
		return NewReservedEngine(config, options, reservation, environment)
	})
}

// PrepareReservedRecordsWithEnvironmentBorrow uses the original plan's already
// admitted Environment reference. The private READY owner remains this exact
// FinishedHandshake; no quota or reference slot is acquired during assembly.
func (f *FinishedHandshake) PrepareReservedRecordsWithEnvironmentBorrow(config Config, options EngineResourceOptions, reservation, environmentBorrow resourcev4.Reference) (*Engine, error) {
	return f.prepareRecords(config, func(config Config) (*Engine, error) {
		return NewReservedEngineWithEnvironmentBorrow(config, options, reservation, environmentBorrow)
	})
}

func (f *FinishedHandshake) prepareRecords(config Config, construct func(Config) (*Engine, error)) (*Engine, error) {
	if !f.mu.TryLock() {
		return nil, ErrCapacity
	}
	defer f.mu.Unlock()
	if !f.live() || f.records != nil || f.localSigned {
		return nil, ErrHandshake
	}
	contract := f.config.Session.Contract.Limits()
	if err := CheckRecordContract(config, f.config.Session.Contract); err != nil {
		return nil, err
	}
	config.SignedMaxScopes = contract.MaxStreams
	config.Profile = f.config.Profile
	config.ApplicationProfile = contract.ApplicationProfile
	config.Root = f.root
	config.HandshakeHash = f.hash
	config.ContextDigest = f.config.ContextDigest
	config.Features = f.config.Features
	config.RootBorn = f.born
	config.SendDirection = f.config.Role
	config.Clock = f.config.Clock
	config.AuthorizationDeadlineMS = f.config.SessionDeadlineMS
	config.Authorization = f.config.Authorization
	config.IdleDurationMS = contract.IdleDurationMS
	config.LocalIdleDurationMS = f.config.LocalIdleDurationMS
	// The handshake deadline governs establishing the Session; the separately
	// authenticated Session deadline in Config governs its admitted lifetime.
	engine, err := construct(config)
	clear(config.Root[:])
	if err != nil {
		f.closed.Store(true)
		f.cleanup()
		return nil, err
	}
	if !f.live() {
		engine.Close()
		_ = engine.Retire()
		f.cleanup()
		return nil, ErrHandshake
	}
	engine.session = f.config.Session
	engine.initial = f
	f.records = engine
	return engine, nil
}

// StartRecords transfers the original private engine only after both READY
// facts. Existing receive frontiers and retained early input are not reset.
func (f *FinishedHandshake) StartRecords() (*Engine, error) {
	if !f.mu.TryLock() {
		return nil, ErrCapacity
	}
	defer f.mu.Unlock()
	if !f.live() || f.records == nil || !f.localSubmitted || !f.peerVerified {
		return nil, ErrNotReady
	}
	engine := f.records
	engine.mu.Lock()
	err := engine.initialLive(f)
	if err == nil {
		err = engine.startIdle()
	}
	if err == nil {
		engine.ready = true
		engine.initial = nil
		f.records = nil
	}
	engine.mu.Unlock()
	f.closed.Store(true)
	f.cleanup()
	if err != nil {
		return nil, err
	}
	return engine, nil
}
