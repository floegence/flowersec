package cryptov4

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrRekey = errors.New("cryptov4: invalid rekey transaction")

// RekeyRound owns one original transaction. It never exports roots, derived
// secrets or ephemeral private material. The Session separately owns barriers,
// cause/credit admission and publication. No crypto runs under the Engine gate.
type RekeyRound struct {
	mu                                   sync.Mutex
	engine                               *Engine
	epoch                                *epochState
	deadline                             *timev4.Deadline
	busy, closed                         bool
	state                                uint8
	id                                   [16]byte
	secret, root, transcript, initDigest [32]byte
	born                                 timev4.Sample
	rootAge                              *timev4.Deadline
	ephemeral                            *DHKey
	peerPublic                           []byte
	init, reply, scratch, barrier        []byte
	initSize, replySize                  int
	receiveTicket                        func() error
}

// BeginRekey reserves the engine's sole round before allocating its bounded
// storage or generating any ephemeral. deadline is the original admitted round
// deadline and cannot be refreshed by a phase or repeated request.
func (e *Engine) BeginRekey(deadlineMS uint64) (*RekeyRound, error) {
	e.mu.Lock()
	if err := e.live(); err != nil {
		e.mu.Unlock()
		return nil, err
	}
	if e.rekey != nil || e.staged != nil || uint64(e.current.number)+1 >= e.limits.Epochs || deadlineMS == 0 {
		e.mu.Unlock()
		return nil, ErrTransition
	}
	deadline, err := timev4.NewDeadline(e.config.Clock, min(deadlineMS, e.current.deadline.Cap()))
	if err != nil {
		e.mu.Unlock()
		return nil, securityTimeError(err)
	}
	r := &RekeyRound{engine: e, epoch: e.current, deadline: deadline, busy: true}
	e.rekey = r
	root := e.current.root
	e.mu.Unlock()
	defer clear(root[:])
	wire, err := handshakeWire()
	if err == nil {
		maximum := int(e.config.MaxFrame) - protocolv4.RecordHeaderSize() - e.profile.TagBytes
		if limit := wire.bounds["REKEY_REPLY"]; limit > 0 {
			maximum = min(maximum, limit)
		}
		if maximum <= 0 {
			err = ErrConfiguration
		} else {
			r.init = make([]byte, maximum)
			r.reply = make([]byte, maximum)
			r.scratch = make([]byte, maximum)
			r.barrier = make([]byte, maximum)
			var info, secret []byte
			info, err = r.domain("rekey_secret", "", nil)
			if err == nil {
				secret, err = hkdf.Expand(sha256.New, root[:], string(info), 32)
			}
			copy(r.secret[:], secret)
			clear(secret)
		}
	}
	clear(root[:])
	if err = r.end(err); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RekeyRound) live() error {
	e := r.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	if e.rekey != r || e.current != r.epoch {
		return ErrTransition
	}
	if err := r.deadline.Check(); err != nil {
		return securityTimeError(err)
	}
	if r.rootAge != nil {
		return securityTimeError(r.rootAge.Check())
	}
	return nil
}

// TightenDeadline joins a newly acquired original security cause. It cannot
// refresh or extend this round, even while a bounded crypto job is running.
func (r *RekeyRound) TightenDeadline(deadlineMS uint64) {
	if deadlineMS == 0 {
		return
	}
	_ = r.deadline.Tighten(min(deadlineMS, r.deadline.Cap()))
}

// DeadlineRemainingMS lets the original Session coordinator observe the same
// immutable round cap without acquiring a crypto job or moving its frontier.
func (r *RekeyRound) DeadlineRemainingMS() (uint64, error) {
	remaining, err := r.deadline.RemainingMS()
	return remaining, securityTimeError(err)
}

func (r *RekeyRound) begin() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.busy {
		return ErrCapacity
	}
	if err := r.live(); err != nil {
		return err
	}
	r.busy = true
	return nil
}

func (r *RekeyRound) end(err error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		err = r.live()
	}
	if r.closed && err == nil {
		err = ErrClosed
	}
	r.busy = false
	r.engine.wakeReceive()
	if err != nil {
		r.closed = true
		r.cleanup()
	}
	return err
}

// endUnattempted releases only a busy claim. Contention before authentication
// has no cryptographic effect and must not destroy the original rekey owner.
func (r *RekeyRound) endUnattempted() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.busy = false
	if r.closed {
		r.cleanup()
		return ErrClosed
	}
	if err := r.live(); err != nil {
		r.closed = true
		r.cleanup()
		return err
	}
	return ErrCapacity
}

func (r *RekeyRound) cleanup() {
	if r.engine == nil {
		return
	}
	r.receiveTicket = nil
	clear(r.secret[:])
	clear(r.root[:])
	clear(r.scratch)
	clear(r.init)
	clear(r.reply)
	clear(r.barrier)
	r.init, r.reply, r.scratch, r.barrier = nil, nil, nil, nil
	if r.ephemeral != nil {
		r.ephemeral.Close()
		r.ephemeral = nil
	}
	clear(r.peerPublic)
	r.peerPublic = nil
	e := r.engine
	r.engine, r.epoch = nil, nil
	// Keep the original deadline observable while Session reconciles its ACK
	// completion. A successful crypto completion is not a deadline failure;
	// this immutable owner supplies no right to begin another crypto job.
	r.rootAge = nil
	e.mu.Lock()
	if e.rekey == r {
		e.rekey = nil
	}
	e.finishCleanupLocked()
	e.mu.Unlock()
}

// PrepareInit completes the client's one ephemeral/ID job before the atomic
// application freeze. A round cannot prepare twice or borrow a pooled key.
func (r *RekeyRound) PrepareInit() (err error) {
	if err = r.begin(); err != nil {
		return err
	}
	defer func() { err = r.end(err) }()
	if r.engine.config.SendDirection != protocolv4.ClientToServer || r.state != 0 || r.ephemeral != nil {
		return ErrRekey
	}
	if _, err = rand.Read(r.id[:]); err != nil {
		return err
	}
	r.ephemeral, err = GenerateDHKey(r.engine.config.Profile)
	return err
}

// Close invalidates publication immediately. An in-progress crypto operation
// keeps its original storage until end; a late result cannot become usable.
func (r *RekeyRound) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if !r.busy {
		r.cleanup()
	}
}

// Check keeps a waiting barrier subject to the original security deadline.
// It never moves that deadline or creates another phase/crypto operation.
func (r *RekeyRound) Check() error {
	if err := r.begin(); err != nil {
		return err
	}
	return r.end(nil)
}

func (r *RekeyRound) domain(name, schema string, extra map[string][]byte) ([]byte, error) {
	e := r.engine
	values := map[string][]byte{"profile": []byte(e.config.Profile), "handshake_hash": e.config.HandshakeHash[:], "context_digest": e.config.ContextDigest[:], "rekey_id": r.id[:]}
	for k, v := range extra {
		values[k] = v
	}
	numbers := map[string]uint64{"epoch": uint64(r.epoch.number), "next_epoch": uint64(r.epoch.number) + 1}
	if schema != "" {
		phase, role, err := protocolv4.RekeyPhaseInfo(schema)
		if err != nil {
			return nil, err
		}
		numbers["phase"], numbers["role"] = phase, uint64(role)
	}
	return cryptoInput(name, values, numbers)
}

func (r *RekeyRound) mac(schema string, unsigned []byte) ([]byte, error) {
	info, err := r.domain("rekey_confirm_key", schema, nil)
	if err != nil {
		return nil, err
	}
	base := r.secret[:]
	if schema == "REKEY_COMMIT" || schema == "REKEY_ACK" {
		base = r.root[:]
	}
	key, err := hkdf.Expand(sha256.New, base, string(info), 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	input, err := r.domain("rekey_confirm_mac", schema, map[string][]byte{"message": unsigned})
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(input)
	return m.Sum(nil), nil
}

func (r *RekeyRound) encode(dst []byte, schema string, fields []protocolv4.Field) ([]byte, error) {
	phase, err := protocolv4.ConstantField(schema, "phase")
	if err != nil {
		return nil, err
	}
	fields = append(fields, phase, protocolv4.Field{Name: "rekey_id", Kind: protocolv4.ByteString, Bytes: r.id[:]}, protocolv4.Field{Name: "next_epoch", Number: uint64(r.epoch.number) + 1})
	u, err := protocolv4.EncodeMACProjection(r.scratch, schema, fields)
	if err != nil {
		return nil, err
	}
	mac, err := r.mac(schema, u)
	if err != nil {
		return nil, err
	}
	defer clear(mac)
	return protocolv4.EncodeMap(dst, schema, append(fields, protocolv4.Field{Name: "confirmation_mac", Kind: protocolv4.ByteString, Bytes: mac}))
}

func (r *RekeyRound) verify(frame *protocolv4.Frame, schema string) error {
	if frame == nil || frame.Type != protocolv4.FrameRekey || frame.Schema != schema || frame.Header.Scope != 0 {
		return ErrRekey
	}
	epoch := r.epoch.number
	if schema == "REKEY_COMMIT" || schema == "REKEY_ACK" {
		epoch++
		if frame.Header.Sequence != 0 {
			return ErrRekey
		}
	}
	if frame.Header.Epoch != epoch {
		return ErrRekey
	}
	id, _ := frame.Field("rekey_id").ByteString()
	next, ok := frame.Field("next_epoch").Uint()
	if !ok || next != uint64(r.epoch.number)+1 || !bytes.Equal(id, r.id[:]) {
		return ErrRekey
	}
	u, err := frame.CopyMACProjection(r.scratch)
	if err != nil {
		return err
	}
	mac, err := r.mac(schema, u)
	if err != nil {
		return err
	}
	defer clear(mac)
	actual, _ := frame.Field("confirmation_mac").ByteString()
	if !hmac.Equal(mac, actual) {
		return ErrRekey
	}
	return nil
}

func (r *RekeyRound) digestInit() error {
	input, err := r.domain("rekey_init_digest", "", map[string][]byte{"init": r.init[:r.initSize]})
	if err == nil {
		r.initDigest = sha256.Sum256(input)
	}
	return err
}

// BuildInit is called after the client has frozen its actual application ticket
// snapshot. dst receives a copy; later caller mutation cannot change the round.
func (r *RekeyRound) BuildInit(dst []byte, entries []protocolv4.RecordHeader) (out []byte, err error) {
	if err = r.begin(); err != nil {
		return nil, err
	}
	defer func() {
		err = r.end(err)
		if err != nil {
			out = nil
		}
	}()
	if r.engine.config.SendDirection != protocolv4.ClientToServer || r.state != 0 || r.ephemeral == nil {
		return nil, ErrRekey
	}
	barrier, err := protocolv4.EncodeBarrier(r.barrier, entries)
	if err != nil {
		return nil, err
	}
	wire, err := r.encode(r.init, "REKEY_INIT", []protocolv4.Field{{Name: "client_ephemeral", Kind: protocolv4.ByteString, Bytes: r.ephemeral.PublicKey()}, {Name: "client_barrier", Kind: protocolv4.EncodedArray, Bytes: barrier}})
	if err != nil {
		return nil, err
	}
	if len(dst) < len(wire) {
		return nil, ErrCapacity
	}
	r.initSize = len(wire)
	if err = r.digestInit(); err != nil {
		return nil, err
	}
	r.state = 1
	return dst[:copy(dst, wire)], nil
}

// AcceptInit verifies the exact original phase before the Session freezes the
// server's snapshot. The frame must come from the original authenticated reader.
func (r *RekeyRound) AcceptInit(frame *protocolv4.Frame) (err error) {
	return r.AcceptInitTicket(frame, nil)
}

// AcceptInitTicket joins original bounded accounting to the first authenticated
// INIT. The hook has SealBuildTicket's restrictions and cannot reenter the engine.
func (r *RekeyRound) AcceptInitTicket(frame *protocolv4.Frame, ticket func() error) (err error) {
	if err = r.begin(); err != nil {
		return err
	}
	defer func() { err = r.end(err) }()
	if r.engine.config.SendDirection != protocolv4.ServerToClient || r.state != 0 || frame == nil || frame.Schema != "REKEY_INIT" {
		return ErrRekey
	}
	id, ok := frame.Field("rekey_id").ByteString()
	if !ok || len(id) != len(r.id) {
		return ErrRekey
	}
	copy(r.id[:], id)
	if err = r.verify(frame, "REKEY_INIT"); err != nil {
		return err
	}
	wire := frame.Document.Bytes()
	if len(wire) > len(r.init) {
		return ErrCapacity
	}
	r.initSize = copy(r.init, wire)
	peer, _ := frame.Field("client_ephemeral").ByteString()
	r.peerPublic = bytes.Clone(peer)
	if err = r.digestInit(); err != nil {
		return err
	}
	if ticket != nil {
		if err = ticket(); err != nil {
			return err
		}
	}
	r.state = 1
	return nil
}

// BindMarkerAccounting installs one receive accounting hook before INIT.
// It runs only after original phase/MAC/frontier verification.
func (r *RekeyRound) BindMarkerAccounting(hook func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if hook == nil || r.closed || r.busy || r.state != 0 || r.receiveTicket != nil {
		return ErrTransition
	}
	r.receiveTicket = hook
	return nil
}

// BuildReply fixes the unique reply and candidate while the server may still
// be waiting for its peer barrier. It grants no publication or key authority.
func (r *RekeyRound) BuildReply(dst []byte, entries []protocolv4.RecordHeader) (out []byte, err error) {
	if err = r.begin(); err != nil {
		return nil, err
	}
	defer func() {
		err = r.end(err)
		if err != nil {
			out = nil
		}
	}()
	if r.engine.config.SendDirection != protocolv4.ServerToClient || r.state != 1 {
		return nil, ErrRekey
	}
	if r.ephemeral, err = GenerateDHKey(r.engine.config.Profile); err != nil {
		return nil, err
	}
	barrier, err := protocolv4.EncodeBarrier(r.barrier, entries)
	if err != nil {
		return nil, err
	}
	wire, err := r.encode(r.reply, "REKEY_REPLY", []protocolv4.Field{{Name: "init_digest", Kind: protocolv4.ByteString, Bytes: r.initDigest[:]}, {Name: "server_ephemeral", Kind: protocolv4.ByteString, Bytes: r.ephemeral.PublicKey()}, {Name: "server_barrier", Kind: protocolv4.EncodedArray, Bytes: barrier}})
	if err != nil {
		return nil, err
	}
	if len(dst) < len(wire) {
		return nil, ErrCapacity
	}
	r.replySize = len(wire)
	if err = r.deriveCandidate(); err != nil {
		return nil, err
	}
	r.state = 2
	return dst[:copy(dst, wire)], nil
}

func (r *RekeyRound) AcceptReply(frame *protocolv4.Frame) (err error) {
	if err = r.begin(); err != nil {
		return err
	}
	defer func() { err = r.end(err) }()
	if r.engine.config.SendDirection != protocolv4.ClientToServer || r.state != 1 {
		return ErrRekey
	}
	if err = r.verify(frame, "REKEY_REPLY"); err != nil {
		return err
	}
	digest, _ := frame.Field("init_digest").ByteString()
	if !bytes.Equal(digest, r.initDigest[:]) {
		return ErrRekey
	}
	wire := frame.Document.Bytes()
	if len(wire) > len(r.reply) {
		return ErrCapacity
	}
	r.replySize = copy(r.reply, wire)
	peer, _ := frame.Field("server_ephemeral").ByteString()
	r.peerPublic = bytes.Clone(peer)
	if err = r.deriveCandidate(); err != nil {
		return err
	}
	r.state = 2
	return nil
}

func (r *RekeyRound) deriveCandidate() error {
	if err := r.live(); err != nil {
		return err
	}
	input, err := r.domain("rekey_transcript", "", map[string][]byte{"init": r.init[:r.initSize], "reply": r.reply[:r.replySize]})
	if err != nil {
		return err
	}
	r.transcript = sha256.Sum256(input)
	dh, err := r.ephemeral.SharedSecret(r.peerPublic)
	if err != nil {
		return err
	}
	defer clear(dh)
	info, err := r.domain("rekey_root", "", map[string][]byte{"transcript_digest": r.transcript[:]})
	if err != nil {
		return err
	}
	// Conservatively charge age from the actual start of the KDF operation.
	r.born, err = r.deadline.Sample()
	if err != nil {
		return securityTimeError(err)
	}
	r.rootAge, err = r.engine.rootDeadline(r.born)
	if err != nil {
		return err
	}
	prk, err := hkdf.Extract(sha256.New, dh, r.secret[:])
	if err != nil {
		return err
	}
	defer clear(prk)
	root, err := hkdf.Expand(sha256.New, prk, string(info), 32)
	if err != nil {
		return err
	}
	copy(r.root[:], root)
	clear(root)
	r.ephemeral.Close()
	r.ephemeral = nil
	r.peerPublic = nil
	return r.live()
}

func (r *RekeyRound) buildMarker(dst []byte, schema string, frontier uint64) ([]byte, error) {
	return r.encode(dst, schema, []protocolv4.Field{{Name: "transcript_digest", Kind: protocolv4.ByteString, Bytes: r.transcript[:]}, {Name: "old_maintenance_next_sequence", Number: frontier}})
}

func (r *RekeyRound) verifyMarker(frame *protocolv4.Frame, schema string, frontier uint64) error {
	if err := r.verify(frame, schema); err != nil {
		return err
	}
	digest, _ := frame.Field("transcript_digest").ByteString()
	n, ok := frame.Field("old_maintenance_next_sequence").Uint()
	if !ok || n != frontier || !bytes.Equal(digest, r.transcript[:]) {
		return ErrRekey
	}
	return nil
}
