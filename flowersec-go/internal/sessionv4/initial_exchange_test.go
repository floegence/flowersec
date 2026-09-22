package sessionv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func initialFixture(t *testing.T, id string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []struct{ ID, Hex string } }
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, v := range corpus.Vectors {
		if v.ID == id {
			b, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatal("missing fixture", id)
	return nil
}

func initialTestConfig(t *testing.T, role protocolv4.Direction, profile string) InitialConfig {
	t.Helper()
	deadline, err := timev4.NewAge(sessionTestClock(t), 60000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	limits := InitialLimits{MaxFrame: 65536, Nodes: 4096}
	charge, err := InitialCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	_, ref := testResourceReservation(t, charge, 1)
	return InitialConfig{Authorization: &revocableAuthorization{}, Reservation: ref, Role: role, Profile: profile, ActivationSourceProfile: "live_authority", Limits: limits, Deadline: deadline}
}

func cleanupInitial(t *testing.T, x *InitialExchange) {
	t.Helper()
	t.Cleanup(func() {
		x.Close(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := x.WaitCleanup(ctx); err != nil {
			t.Error("initial owner leaked", err)
		}
	})
}

func initialCopy(wire []byte) func([]byte) (int, error) {
	return func(dst []byte) (int, error) {
		if len(wire) > len(dst) {
			return 0, io.ErrShortBuffer
		}
		return copy(dst, wire), nil
	}
}

// These fixtures isolate the I/O and crypto owners. Exact-byte verification is
// a test handler, not issuer/admission trust or live provider qualification.
func initialExact(wire []byte) func([]byte) error {
	return func(got []byte) error {
		if !bytes.Equal(got, wire) {
			return ErrInitialPhase
		}
		return nil
	}
}

func initialHelloProfile(t *testing.T, wire []byte, schema, profile string) []byte {
	t.Helper()
	d, err := protocolv4.NewDecoder(16384, 4096)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := d.DecodeMap(wire, schema, protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	var registry struct {
		Maps map[string]struct {
			Fields map[string]struct{ Name string }
		} `json:"frame_maps"`
	}
	if err := json.Unmarshal([]byte(protocolv4.CBORSyntaxRegistryJSON), &registry); err != nil {
		t.Fatal(err)
	}
	var fields []protocolv4.Field
	for _, f := range registry.Maps[schema].Fields {
		v := doc.Root().Named(schema, f.Name)
		field := protocolv4.Field{Name: f.Name}
		if text, ok := v.Text(); ok {
			field.Kind, field.Text = protocolv4.TextString, text
			if f.Name == "crypto_profile_id" {
				field.Text = profile
			}
		} else if b, ok := v.ByteString(); ok {
			field.Kind, field.Bytes = protocolv4.ByteString, b
		} else if n, ok := v.Uint(); ok {
			field.Number = n
		} else {
			t.Fatal("unexpected hello field")
		}
		fields = append(fields, field)
	}
	result, err := protocolv4.EncodeMap(make([]byte, 16384), schema, fields)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type initialMemoryStream struct {
	bytes.Buffer
	readBytes int
	closed    atomic.Bool
}

func (s *initialMemoryStream) Read(p []byte) (int, error) {
	n, err := s.Buffer.Read(p)
	s.readBytes += n
	return n, err
}
func (s *initialMemoryStream) Close() error { s.closed.Store(true); return nil }

func TestInitialExchangeRejectsBeforeBodyAndVerification(t *testing.T) {
	for _, fault := range []string{"oversize", "flags", "reserved", "wrong_phase", "zero", "truncated", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			header := make([]byte, 8)
			binary.BigEndian.PutUint32(header, 212)
			header[4] = byte(protocolv4.FrameNegotiate)
			switch fault {
			case "oversize":
				binary.BigEndian.PutUint32(header, 16385)
			case "flags":
				header[5] = 1
			case "reserved":
				header[7] = 1
			case "wrong_phase":
				header[4] = byte(protocolv4.FrameAdmission)
			case "unknown":
				header[4] = 255
			case "zero":
				binary.BigEndian.PutUint32(header, 0)
			case "truncated":
				header = header[:5]
			}
			stream := &initialMemoryStream{}
			stream.Buffer.Write(header)
			if fault != "truncated" {
				stream.Buffer.Write(make([]byte, 212))
			}
			x, err := NewInitialStream(context.Background(), initialTestConfig(t, protocolv4.ServerToClient, protocolv4.DHProfileX25519), stream)
			if err != nil {
				t.Fatal(err)
			}
			cleanupInitial(t, x)
			called := false
			err = x.Receive(protocolv4.FrameNegotiate, func([]byte) error { called = true; return nil })
			if err == nil || called || stream.readBytes > 8 {
				t.Fatal("body or verifier reached after invalid prefix", stream.readBytes, called, err)
			}
			if err = x.Receive(protocolv4.FrameNegotiate, func([]byte) error { called = true; return nil }); err == nil || called {
				t.Fatal("failed owner reused", err)
			}
		})
	}
}

type initialShortStream struct {
	io.ReadWriteCloser
	calls atomic.Int32
}

func (s *initialShortStream) Write(p []byte) (int, error) {
	s.calls.Add(1)
	return s.ReadWriteCloser.Write(p[:min(7, len(p))])
}

type initialMessagePipe struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
	writes  atomic.Int32
}

func (p *initialMessagePipe) ReadMessage(ctx context.Context, dst []byte) (int, error) {
	select {
	case wire := <-p.in:
		if len(wire) > len(dst) {
			return 0, io.ErrShortBuffer
		}
		return copy(dst, wire), nil
	case <-p.done:
		return 0, io.ErrClosedPipe
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (p *initialMessagePipe) WriteMessage(ctx context.Context, wire []byte) error {
	p.writes.Add(1)
	select {
	case p.out <- bytes.Clone(wire):
		return nil
	case <-p.done:
		return io.ErrClosedPipe
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *initialMessagePipe) Close() error { p.once.Do(func() { close(p.done) }); return nil }

func initialTestPair(t *testing.T, profile, framing string) ([2]*InitialExchange, [2]cryptov4.HandshakeConfig) {
	t.Helper()
	return initialTestPairThrough(t, profile, framing, 4)
}

func initialTestPairThrough(t *testing.T, profile, framing string, flights int, parents ...context.Context) ([2]*InitialExchange, [2]cryptov4.HandshakeConfig) {
	t.Helper()
	return initialTestPairPrepared(t, profile, framing, flights, nil, parents...)
}

func initialTestPairPrepared(t *testing.T, profile, framing string, flights int, prepare func(*cryptov4.HandshakeConfig, *InitialConfig), parents ...context.Context) ([2]*InitialExchange, [2]cryptov4.HandshakeConfig) {
	t.Helper()
	var pair [2]*InitialExchange
	var configs [2]cryptov4.HandshakeConfig
	clock := sessionTestClock(t)
	now, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	fsb, fsa := initialFixture(t, "fsb_fields"), initialFixture(t, "fsa_admitted_fields")
	d, _ := protocolv4.NewDecoder(16384, 4096)
	doc, err := d.DecodeMap(fsa, "FSA4", protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	get := func(name string) [32]byte { b, _ := doc.Root().Named("FSA4", name).ByteString(); return [32]byte(b) }
	features, _ := doc.Root().Named("FSA4", "selected_features").Uint()
	left, right := net.Pipe()
	streams := [2]*initialShortStream{{ReadWriteCloser: left}, {ReadWriteCloser: right}}
	// Close unused pipe endpoints too when this case uses message framing.
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	a, b := make(chan []byte, 1), make(chan []byte, 1)
	messages := [2]*initialMessagePipe{{in: a, out: b, done: make(chan struct{})}, {in: b, out: a, done: make(chan struct{})}}
	for role := range 2 {
		key, err := cryptov4.GenerateDHKey(profile)
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
		identity := get("client_identity_digest")
		if role == 1 {
			identity = get("server_identity_digest")
		}
		configs[role] = cryptov4.HandshakeConfig{Session: testSessionContract(t, profile, "transport", 4096, 4, 0, now.LowerMS+3600000), Authorization: testAuthorization{}, Profile: profile, Role: protocolv4.Direction(role), PSK: [32]byte{1}, FSB: fsb, FSA: fsa,
			ContextDigest: get("transport_context_digest"), AdmissionBinding: get("admission_binding"), LocalCertificateDigest: identity,
			LocalDH: key, LocalDHPublic: key.PublicKey(), Signer: bootstrapSigner{signing}, Features: features, Deadline: deadline, SessionDeadlineMS: now.LowerMS + 3600000, Clock: clock}
		copy(configs[role].LocalEdPublic[:], signing.Public().(ed25519.PublicKey))
		config := initialTestConfig(t, protocolv4.Direction(role), profile)
		config.Deadline = deadline
		if prepare != nil {
			prepare(&configs[role], &config)
		}
		parent := context.Background()
		if len(parents) != 0 {
			parent = parents[role]
		}
		if framing == "stream" {
			pair[role], err = NewInitialStream(parent, config, streams[role])
		} else {
			pair[role], err = NewInitialMessages(parent, config, messages[role])
		}
		if err != nil {
			t.Fatal(err)
		}
		pair[role].session = configs[role].Session
		cleanupInitial(t, pair[role])
	}
	for role := range 2 {
		peer := configs[1-role]
		configs[role].PeerCertificateDigest, configs[role].PeerDHPublic, configs[role].PeerEdPublic = peer.LocalCertificateDigest, peer.LocalDHPublic, peer.LocalEdPublic
	}
	wires := [][]byte{initialHelloProfile(t, initialFixture(t, "client_hello_fields"), "ClientHello", profile), initialHelloProfile(t, initialFixture(t, "server_hello_fields"), "ServerHello", profile), fsb, fsa}
	for phase, wire := range wires[:flights] {
		frame, sender := initialFlight(uint8(phase))
		result := make(chan error, 1)
		go func() { result <- pair[1-sender].Receive(frame, initialExact(wire)) }()
		written, err := pair[sender].Send(frame, initialCopy(wire))
		if err != nil {
			t.Fatal("send", phase, written, err)
		}
		if err = <-result; err != nil {
			t.Fatal("receive", phase, err)
		}
	}
	return pair, configs
}

func initialRecordLimits() cryptov4.Config {
	return cryptov4.Config{MaxFrame: 4096, MaxScopes: 4, PendingScopes: 2, WorkSlots: 2, Maintenance: cryptov4.MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}}
}

func TestInitialExchangeNoiseReadyAndEncryptedRecords(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		for _, framing := range []string{"stream", "message"} {
			t.Run(profile+"/"+framing, func(t *testing.T) {
				var parents [2]context.Context
				var stops [2]context.CancelFunc
				for role := range 2 {
					parents[role], stops[role] = context.WithCancel(context.Background())
					defer stops[role]()
				}
				pair, configs := initialTestPairThrough(t, profile, framing, 4, parents[:]...)
				streams := [2]io.ReadWriteCloser{pair[0].stream, pair[1].stream}
				messages := [2]InitialMessages{pair[0].messages, pair[1].messages}
				type result struct {
					engine *cryptov4.Engine
					err    error
				}
				results := [2]chan result{make(chan result, 1), make(chan result, 1)}
				var reservations [2]atomic.Int32
				for role := range 2 {
					go func() {
						e, err := pair[role].Authenticate(configs[role], initialRecordLimits(), func(e *cryptov4.Engine) error {
							reservations[role].Add(1)
							if err := e.ApplicationInputReady(0); !errors.Is(err, cryptov4.ErrNotReady) {
								return ErrInitialPhase
							}
							return nil
						})
						results[role] <- result{e, err}
					}()
				}
				var engines [2]*cryptov4.Engine
				for role := range 2 {
					r := <-results[role]
					if r.err != nil || r.engine == nil || reservations[role].Load() != 1 {
						t.Fatal("authentication", role, r.err)
					}
					engines[role] = r.engine
					t.Cleanup(r.engine.Close)
					// The completed original handshake no longer owns cancellation
					// of this carrier or its transferred authorization.
					stops[role]()
					if err := r.engine.ApplicationInputReady(0); err != nil {
						t.Fatal(err)
					}
					if _, err := pair[role].Authenticate(configs[role], initialRecordLimits(), func(*cryptov4.Engine) error { return nil }); err == nil {
						t.Fatal("second delivery")
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					if err := pair[role].WaitCleanup(ctx); err != nil {
						t.Fatal(err)
					}
					cancel()
					pair[role].Close(nil)
					if err := pair[role].config.Authorization.Check(); err != nil {
						t.Fatal("completed handshake reclaimed the transferred authorization", err)
					}
				}
				packet, err := engines[0].Seal(protocolv4.FramePing, 0, []byte("encrypted after READY"))
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Release()
				wire, err := packet.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				received := make([]byte, len(wire))
				if framing == "stream" {
					for _, stream := range streams {
						if err := stream.(*initialShortStream).ReadWriteCloser.(net.Conn).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
							t.Fatal(err)
						}
					}
					written := make(chan error, 1)
					go func() {
						for offset := 0; offset < len(wire); {
							n, err := streams[0].Write(wire[offset:])
							if err != nil || n == 0 {
								if err == nil {
									err = io.ErrNoProgress
								}
								written <- err
								return
							}
							offset += n
						}
						written <- nil
					}()
					if _, err := io.ReadFull(streams[1], received); err != nil {
						t.Fatal("transferred stream closed with handshake context", err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
				} else {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := messages[0].WriteMessage(ctx, wire); err != nil {
						t.Fatal("transferred message carrier closed with handshake context", err)
					}
					if n, err := messages[1].ReadMessage(ctx, received); err != nil || n != len(wire) {
						t.Fatal("transferred message carrier read failed", n, err)
					}
				}
				got, _, _, err := engines[1].Open(received, func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				defer got.Release()
				plaintext, err := got.Bytes()
				if err != nil || string(plaintext) != "encrypted after READY" {
					t.Fatal(err)
				}
				engines[0].Close()
				if err := pair[0].config.Authorization.Check(); !errors.Is(err, errAuthorizationRejected) {
					t.Fatal("record engine did not release original authorization", err)
				}
			})
		}
	}
}

func TestInitialExchangeRefusesReplacementBeforeNoise(t *testing.T) {
	for _, field := range []string{"fsb", "fsa", "context", "binding", "identity", "profile", "features", "deadline", "contract", "artifact", "issued", "expiry", "missing_contract"} {
		t.Run(field, func(t *testing.T) {
			pair, configs := initialTestPair(t, protocolv4.DHProfileX25519, "message")
			c := configs[0]
			switch field {
			case "contract":
				c.Session.Contract = testSessionContract(t, c.Profile, "transport", 8192, 4, 0, c.SessionDeadlineMS).Contract
			case "artifact":
				c.Session.ArtifactDigest[0] ^= 1
			case "issued":
				c.Session.IssuedAtMS++
			case "expiry":
				c.Session.SessionNotAfterMS++
			case "missing_contract":
				c.Session.Contract = protocolv4.SessionContract{}
			case "fsb":
				c.FSB = bytes.Clone(c.FSB)
				c.FSB[len(c.FSB)-1] ^= 1
			case "fsa":
				c.FSA = bytes.Clone(c.FSA)
				c.FSA[len(c.FSA)-1] ^= 1
			case "context":
				c.ContextDigest[0] ^= 1
			case "binding":
				c.AdmissionBinding[0] ^= 1
			case "identity":
				c.PeerCertificateDigest[0] ^= 1
			case "profile":
				c.Profile = protocolv4.DHProfileP256
			case "features":
				c.Features ^= 1
			case "deadline":
				c.Deadline = initialTestConfig(t, 0, c.Profile).Deadline
			}
			called := false
			if e, err := pair[0].Authenticate(c, initialRecordLimits(), func(*cryptov4.Engine) error { called = true; return nil }); e != nil || !errors.Is(err, ErrInitialPhase) || called {
				t.Fatal(e, err, called)
			}
		})
	}
}

func TestInitialExchangeCancelledBuildRetainsRealTail(t *testing.T) {
	stream := &initialMemoryStream{}
	x, err := NewInitialStream(context.Background(), initialTestConfig(t, 0, protocolv4.DHProfileX25519), stream)
	if err != nil {
		t.Fatal(err)
	}
	cleanupInitial(t, x)
	entered, release := make(chan struct{}), make(chan struct{})
	type outcome struct {
		result InitialWriteResult
		err    error
	}
	result := make(chan outcome, 1)
	go func() {
		r, err := x.Send(protocolv4.FrameNegotiate, func(dst []byte) (int, error) {
			dst[0] = 0x7f
			close(entered)
			<-release
			if dst[0] != 0x7f {
				return 0, errors.New("live builder storage was cleared")
			}
			return 0, context.Canceled
		})
		result <- outcome{r, err}
	}()
	<-entered
	second := false
	if _, err := x.Send(protocolv4.FrameNegotiate, func([]byte) (int, error) { second = true; return 0, nil }); !errors.Is(err, cryptov4.ErrCapacity) || second {
		t.Fatal("queued second builder", err)
	}
	x.Close(context.Canceled)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := x.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup before builder exit", err)
	}
	cancel()
	close(release)
	r := <-result
	if !r.result.Started || r.result.Submitted || !errors.Is(r.err, context.Canceled) {
		t.Fatal(r)
	}
	if !stream.closed.Load() {
		t.Fatal("cancel did not stop original provider")
	}
}

type initialBlockedStream struct {
	entered, release chan struct{}
	closed           atomic.Bool
	first            []byte
}

func (s *initialBlockedStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *initialBlockedStream) Write(p []byte) (int, error) {
	s.first = bytes.Clone(p)
	close(s.entered)
	<-s.release
	if !bytes.Equal(p, s.first) {
		return 0, errors.New("provider alias overwritten")
	}
	return 3, io.ErrClosedPipe
}
func (s *initialBlockedStream) Close() error { s.closed.Store(true); return nil }

func TestInitialExchangeCancelledWritePreservesSubmittedAndCleanup(t *testing.T) {
	stream := &initialBlockedStream{entered: make(chan struct{}), release: make(chan struct{})}
	x, err := NewInitialStream(context.Background(), initialTestConfig(t, 0, protocolv4.DHProfileX25519), stream)
	if err != nil {
		t.Fatal(err)
	}
	cleanupInitial(t, x)
	wire := initialFixture(t, "client_hello_fields")
	finished := make(chan InitialWriteResult, 1)
	go func() { r, _ := x.Send(protocolv4.FrameNegotiate, initialCopy(wire)); finished <- r }()
	<-stream.entered
	x.Close(context.Canceled)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := x.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("provider tail released", err)
	}
	cancel()
	close(stream.release)
	r := <-finished
	if !r.Started || !r.Submitted || r.Complete || r.EnvelopeBytes != 3 {
		t.Fatal(r)
	}
	called := false
	if _, err := x.Send(protocolv4.FrameNegotiate, func([]byte) (int, error) { called = true; return 0, nil }); err == nil || called {
		t.Fatal("replayed partial flight", err)
	}
}

func TestInitialExchangeMessageBoundaryAndDuplicateRejection(t *testing.T) {
	for _, fault := range []string{"two_envelopes", "split_envelope", "trailing", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			wire, _ := (protocolv4.Envelope{FrameType: protocolv4.FrameNegotiate, Payload: initialFixture(t, "client_hello_fields")}).Encode()
			input := bytes.Clone(wire)
			switch fault {
			case "two_envelopes":
				input = append(input, wire...)
			case "split_envelope":
				input = input[:len(input)/2]
			case "trailing":
				input = append(input, 0)
			}
			p := &initialMessagePipe{in: make(chan []byte, 2), out: make(chan []byte, 2), done: make(chan struct{})}
			p.in <- input
			x, err := NewInitialMessages(context.Background(), initialTestConfig(t, 1, protocolv4.DHProfileX25519), p)
			if err != nil {
				t.Fatal(err)
			}
			cleanupInitial(t, x)
			calls := 0
			err = x.Receive(protocolv4.FrameNegotiate, func([]byte) error { calls++; return nil })
			if fault == "duplicate" {
				if err != nil || calls != 1 {
					t.Fatal(err)
				}
				if _, err = x.Send(protocolv4.FrameNegotiate, initialCopy(initialFixture(t, "server_hello_fields"))); err != nil {
					t.Fatal(err)
				}
				p.in <- wire
				err = x.Receive(protocolv4.FrameAdmission, func([]byte) error { calls++; return nil })
				if calls != 1 {
					t.Fatal("duplicate reached verifier")
				}
			} else if calls != 0 {
				t.Fatal("invalid message reached verifier")
			}
			if err == nil {
				t.Fatal("invalid message accepted")
			}
		})
	}
}

func TestInitialExchangeAuthenticatedRejectionCannotStartNoise(t *testing.T) {
	for _, verified := range []bool{false, true} {
		t.Run(map[bool]string{false: "unauthenticated", true: "authenticated"}[verified], func(t *testing.T) {
			pair, _ := initialTestPairThrough(t, protocolv4.DHProfileX25519, "message", 3)
			x := pair[0]
			p := x.messages.(*initialMessagePipe)
			wire := initialFixture(t, "admission_rejected_activation_proof_invalid")
			envelope, _ := (protocolv4.Envelope{FrameType: protocolv4.FrameAdmissionResult, Payload: wire}).Encode()
			p.in <- envelope
			verificationError := errors.New("untrusted response certificate")
			err := x.Receive(protocolv4.FrameAdmissionResult, func([]byte) error {
				if verified {
					return nil
				}
				return verificationError
			})
			if verified && !errors.Is(err, ErrAdmissionRejected) || !verified && !errors.Is(err, verificationError) {
				t.Fatal(err)
			}
			called := false
			if _, err := x.Send(protocolv4.FrameHandshake, func([]byte) (int, error) { called = true; return 0, nil }); err == nil || called {
				t.Fatal("rejected start", err)
			}
		})
	}
}
