package sessionv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type bootstrapSigner struct{ key ed25519.PrivateKey }

func (s bootstrapSigner) PublicKey() []byte             { return s.key.Public().(ed25519.PublicKey) }
func (s bootstrapSigner) Sign(p []byte) ([]byte, error) { return ed25519.Sign(s.key, p), nil }

type bootstrapEndpoint struct {
	*openEndpoint
	bootstrap *Bootstrap
	handshake *cryptov4.FinishedHandshake
	ready     []byte
	stream    bytes.Buffer
	carrier   *CarrierAssociation
}

func newBootstrapPair(t *testing.T, profile, application string) (*bootstrapEndpoint, *bootstrapEndpoint) {
	return newBootstrapPairWithShared(t, profile, application, false)
}

func newBootstrapPairWithShared(t *testing.T, profile, application string, shared bool) (*bootstrapEndpoint, *bootstrapEndpoint) {
	return newBootstrapPairSetup(t, profile, application, shared, 65536, nil)
}

func newBootstrapPairSetup(t *testing.T, profile, application string, shared bool, maxCredit uint64, setup func(int, *bootstrapEndpoint) *Bootstrap) (*bootstrapEndpoint, *bootstrapEndpoint) {
	t.Helper()
	return newBootstrapPairSetupCapacity(t, profile, application, shared, maxCredit, 4, setup)
}

func newBootstrapPairSetupCapacity(t *testing.T, profile, application string, shared bool, maxCredit uint64, scopes uint32, setup func(int, *bootstrapEndpoint) *Bootstrap) (*bootstrapEndpoint, *bootstrapEndpoint) {
	t.Helper()
	// The cryptographic handshake consumes the shared public FSB/FSA fixture.
	// Certificate/admission trust and provider qualification are separate tests.
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
	clock := sessionTestClock(t)
	now, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	var configs [2]cryptov4.HandshakeConfig
	var handshakes [2]*cryptov4.Handshake
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
		configs[role] = cryptov4.HandshakeConfig{Authorization: testAuthorization{}, Profile: profile, Session: testSessionContract(t, profile, application, 65536, scopes, 0, now.LowerMS+3600000, maxCredit), Role: protocolv4.Direction(role), PSK: [32]byte{1}, FSB: inputs["fsb_fields"], FSA: inputs["fsa_admitted_fields"], ContextDigest: [32]byte{2}, AdmissionBinding: [32]byte{3}, LocalCertificateDigest: [32]byte{byte(role + 4)}, LocalDH: key, LocalDHPublic: key.PublicKey(), Signer: bootstrapSigner{signing}, Features: 1, Deadline: deadline, SessionDeadlineMS: now.LowerMS + 3600000, Clock: clock}
		copy(configs[role].LocalEdPublic[:], signing.Public().(ed25519.PublicKey))
	}
	for role := range 2 {
		peer := configs[1-role]
		configs[role].PeerCertificateDigest, configs[role].PeerDHPublic, configs[role].PeerEdPublic = peer.LocalCertificateDigest, peer.LocalDHPublic, peer.LocalEdPublic
		handshakes[role], err = cryptov4.NewHandshake(configs[role])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(handshakes[role].Close)
	}
	for role := range 2 {
		wire, err := handshakes[role].WriteMessage()
		if err != nil {
			t.Fatal(err)
		}
		if err = handshakes[1-role].ReadMessage(wire); err != nil {
			t.Fatal(err)
		}
	}
	var endpoints [2]*bootstrapEndpoint
	for role := range 2 {
		finished, err := handshakes[role].Finish()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(finished.Close)
		engine, err := finished.PrepareRecords(cryptov4.Config{MaxFrame: 65536, MaxScopes: scopes, PendingScopes: 2, WorkSlots: 4, Maintenance: cryptov4.MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}})
		if err != nil {
			t.Fatal(err)
		}
		limits := OpenLimits{Active: 4, Opening: 2, Terminal: 9, RejectionReserve: 1, IngressItems: 2, IngressBytes: 64 << 10, PerClass: [3]uint32{2, 2}, PerOpener: [2][3]uint32{{2, 2}, {2, 2}}, Protected: [2][3]uint32{{0, 1}}, Lifetime: [2][3]uint64{{1024, 1024}, {1024, 1024}}}
		if scopes > 4 {
			limits.Active, limits.Terminal = scopes, scopes*2+1
			limits.PerClass[InternalStream] = 10
			for role := range 2 {
				limits.PerOpener[role][InternalStream] = 5
				limits.Protected[role][InternalStream] = 5
			}
		}
		if application == "execution" && scopes > 4 {
			limits.PerClass[ManagementStream] = 1
			limits.PerOpener[0][ManagementStream] = 1
			limits.Protected[0][ManagementStream] = 1
			limits.Lifetime[0][ManagementStream] = 16
		}
		a, err := NewOpenAdmission(engine, protocolv4.Direction(role), limits)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(a.Close)
		makeReader := func() *RecordReceiver {
			r, err := newTestRecordReceiver(t, engine, protocolv4.Direction(1-role), 65536, 256, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 16384}})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		pool, err := testReceivePool(t, 65536, 65536)
		if err != nil {
			t.Fatal(err)
		}
		e := &bootstrapEndpoint{openEndpoint: &openEndpoint{t: t, engine: engine, admission: a, receiver: makeReader(), pool: pool}, handshake: finished, carrier: &CarrierAssociation{}}
		e.maintenance, err = NewRecordWriter(engine, 0, &e.control)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := finished.Ready(); !errors.Is(err, cryptov4.ErrNotReady) {
			t.Fatal("READY before bootstrap backing", err)
		}
		if setup != nil {
			e.bootstrap = setup(role, e)
		} else {
			_, send := testSendReservation(t, 16384)
			reservation := StreamReservation{Pool: pool, ReceiveCapacity: 32768, SendCapacity: 16384, SendReservation: send, OpenStorage: make([]byte, 256), InitialReceiveLimit: 16384, MaxPlaintext: 16512}
			if shared {
				g := newSharedIngressForTest(t, e.openEndpoint)
				e.bootstrap, err = g.PrepareBootstrap(reservation, &e.stream)
			} else {
				e.bootstrap, err = a.PrepareBootstrap(BootstrapReservation{StreamReservation: reservation, Receiver: makeReader()})
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		e.ready, err = finished.Ready()
		if err != nil {
			t.Fatal(err)
		}
		if err = finished.MarkReadySubmitted(); err != nil {
			t.Fatal(err)
		}
		endpoints[role] = e
	}
	return endpoints[0], endpoints[1]
}

func (e *bootstrapEndpoint) complete(t *testing.T, peer *bootstrapEndpoint) {
	t.Helper()
	if err := e.handshake.VerifyReady(peer.ready); err != nil {
		t.Fatal(err)
	}
	engine, err := e.handshake.StartRecords()
	if err != nil || engine != e.engine {
		t.Fatal(err)
	}
	if err = e.bootstrap.Complete(); err != nil {
		t.Fatal(err)
	}
}

func (e *bootstrapEndpoint) bindPrefix(t *testing.T, client *bootstrapEndpoint) {
	t.Helper()
	record, err := e.bootstrap.reader.ReadOpen(context.Background(), &client.stream)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Release()
	if err = e.bootstrap.BindPeerPrefix(record, e.carrier, &e.stream); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapActualPrefixAndPrivateDataBeforePeerReady(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		for _, application := range []string{"services", "execution"} {
			t.Run(profile+"/"+application, func(t *testing.T) {
				ctx := context.Background()
				client, server := newBootstrapPair(t, profile, application)
				client.complete(t, server)
				if _, err := server.bootstrap.Creation(); !errors.Is(err, cryptov4.ErrNotReady) {
					t.Fatal(err)
				}
				for _, e := range []*bootstrapEndpoint{client, server} {
					if usage := e.admission.Usage(); usage.Active != 1 || usage.PositiveProofs != 1 || usage.Opening != 0 || usage.Pending != 0 {
						t.Fatal(usage)
					}
					if e.pool.Outstanding() != 16384 || e.admission.lifetime[0][InternalStream] != 1 {
						t.Fatal("bootstrap not charged exactly once")
					}
					if _, err := e.admission.Flow(e.bootstrap.Handle()); !errors.Is(err, ErrOpenPending) {
						t.Fatal("unbound bootstrap exposed", err)
					}
				}
				if client.admission.nextOrdinal != 2 || server.admission.nextOrdinal != 1 {
					t.Fatal("bootstrap advanced wrong allocator")
				}
				if err := client.bootstrap.BindLocalCarrier(client.carrier, &client.stream); err != nil {
					t.Fatal(err)
				}
				result, err := client.bootstrap.PublishPrefix(ctx)
				if err != nil || !result.Submitted || result.Header.Sequence != 0 {
					t.Fatal(result, err)
				}
				server.bindPrefix(t, client)
				flow, err := client.admission.Flow(client.bootstrap.Handle())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = flow.send.Write(ctx, []byte("early application bytes"), false); err != nil {
					t.Fatal(err)
				}
				record, err := server.bootstrap.reader.Read(ctx, &client.stream)
				if err != nil {
					t.Fatal(err)
				}
				if err = server.admission.ApplyData(server.bootstrap.Handle(), server.carrier, record); err != nil {
					t.Fatal(err)
				}
				record.Release()
				if _, err = server.admission.Flow(server.bootstrap.Handle()); !errors.Is(err, ErrOpenPending) {
					t.Fatal("private DATA exposed", err)
				}
				server.complete(t, client)
				flow, err = server.admission.Flow(server.bootstrap.Handle())
				if err != nil {
					t.Fatal(err)
				}
				var dst [64]byte
				n, terminal, err := flow.receive.TryRead(dst[:])
				if err != nil || terminal != protocolv4.V4ReadTerminalOpen || string(dst[:n]) != "early application bytes" {
					t.Fatal(n, terminal, err)
				}
				frontier, err := server.engine.ScopeFrontier(1, protocolv4.ClientToServer)
				if err != nil || frontier.Sequence != 2 {
					t.Fatal("READY reset prefix/DATA frontier", frontier, err)
				}
				if _, err = flow.send.Write(ctx, []byte("reverse"), false); err != nil {
					t.Fatal(err)
				}
				record, err = client.bootstrap.reader.Read(ctx, &server.stream)
				if err != nil {
					t.Fatal(err)
				}
				if err = client.admission.ApplyData(client.bootstrap.Handle(), client.carrier, record); err != nil {
					t.Fatal(err)
				}
				record.Release()
				creation, err := server.bootstrap.Creation()
				if err != nil || creation.Variant != "bootstrap_ready" || !creation.LocalSubmitted || !creation.PeerVerified || creation.ApplicationProfile != application {
					t.Fatal(creation, err)
				}
				if server.control.Len() != 0 || client.control.Len() != 0 {
					t.Fatal("bootstrap emitted an OPEN outcome")
				}
			})
		}
	}
}

func TestBootstrapZeroFrontierSurvivesRekeyBeforePrefix(t *testing.T) {
	ctx := context.Background()
	client, server := newBootstrapPair(t, protocolv4.DHProfileX25519, "services")
	client.complete(t, server)
	server.complete(t, client)
	cx, sx := exchange(t, client.openEndpoint), exchange(t, server.openEndpoint)
	if _, err := cx.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.bootstrap.BindLocalCarrier(client.carrier, &client.stream); err != nil {
		t.Fatal(err)
	}
	if result, err := client.bootstrap.PublishPrefix(ctx); !errors.Is(err, cryptov4.ErrTransition) || result.Submitted {
		t.Fatal("prefix bypassed freeze", result, err)
	}
	exchangeFlight(t, client.openEndpoint, server.openEndpoint, sx)
	exchangeProgress(t, sx)
	exchangeFlight(t, server.openEndpoint, client.openEndpoint, cx)
	exchangeProgress(t, cx)
	exchangeFlight(t, client.openEndpoint, server.openEndpoint, sx)
	exchangeProgress(t, sx)
	exchangeFlight(t, server.openEndpoint, client.openEndpoint, cx)
	// The still-unmaterialized scope retains its identity through another
	// complete epoch; no await-OPEN or replacement ordinal is introduced.
	var err error
	cx, err = NewRekeyExchange(client.admission, client.admission.barriers, client.maintenance, rekeyTestDeadline(t, client.engine), RekeyPhaseBudgets{5000, 10000, 30000})
	if err != nil {
		t.Fatal(err)
	}
	sx, err = NewRekeyExchange(server.admission, server.admission.barriers, server.maintenance, rekeyTestDeadline(t, server.engine), RekeyPhaseBudgets{5000, 10000, 30000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cx.Start(ctx); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, client.openEndpoint, server.openEndpoint, sx)
	exchangeProgress(t, sx)
	exchangeFlight(t, server.openEndpoint, client.openEndpoint, cx)
	exchangeProgress(t, cx)
	exchangeFlight(t, client.openEndpoint, server.openEndpoint, sx)
	exchangeProgress(t, sx)
	exchangeFlight(t, server.openEndpoint, client.openEndpoint, cx)
	result, err := client.bootstrap.PublishPrefix(ctx)
	if err != nil || result.Header.Epoch != 2 || result.Header.Sequence != 0 {
		t.Fatal(result, err)
	}
	server.bindPrefix(t, client)
	if client.admission.nextOrdinal != 2 || server.admission.lifetime[0][InternalStream] != 1 {
		t.Fatal("rekey recreated bootstrap")
	}
	for _, e := range []*bootstrapEndpoint{client, server} {
		if _, err = e.admission.Flow(e.bootstrap.Handle()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBootstrapRejectsChangedPrefixAndUnexpectedOutcome(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"kind", "metadata", "credit"} {
		t.Run(change, func(t *testing.T) {
			client, server := newBootstrapPair(t, protocolv4.DHProfileX25519, "services")
			client.complete(t, server)
			server.complete(t, client)
			spec := client.bootstrap.spec
			metadata := []byte(nil)
			switch change {
			case "kind":
				spec.Kind = "other.kind"
			case "metadata":
				metadata = []byte{0xa0}
			case "credit":
				spec.ReceiveLimit++
			}
			packet, err := client.engine.SealBuild(protocolv4.FrameOpenStream, spec.Scope, 256, func(h protocolv4.RecordHeader, dst []byte) (int, error) {
				wire, _, err := protocolv4.EncodeOpen(dst, h, spec.Opener, spec.Kind, metadata, spec.ReceiveLimit)
				return len(wire), err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			wire, err := packet.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = server.bootstrap.reader.ReceiveOpen(ctx, wire); !errors.Is(err, ErrOpenAssociation) {
				t.Fatal("changed fixed prefix accepted", err)
			}
			frontier, err := server.engine.ScopeFrontier(spec.Scope, spec.Opener)
			if err != nil || frontier.Sequence != 0 {
				t.Fatal("invalid prefix advanced original owner", frontier, err)
			}
		})
	}
	client, server := newBootstrapPair(t, protocolv4.DHProfileP256, "execution")
	client.complete(t, server)
	server.complete(t, client)
	if err := client.bootstrap.BindLocalCarrier(client.carrier, &client.stream); err != nil {
		t.Fatal(err)
	}
	if _, err := client.bootstrap.PublishPrefix(ctx); err != nil {
		t.Fatal(err)
	}
	server.bindPrefix(t, client)
	if err := client.bootstrap.BindLocalCarrier(&CarrierAssociation{}, new(bytes.Buffer)); !errors.Is(err, ErrOpenAssociation) {
		t.Fatal("second native association", err)
	}
	if _, err := client.bootstrap.PublishPrefix(ctx); !errors.Is(err, ErrOpenAssociation) {
		t.Fatal("second bootstrap prefix", err)
	}
	client.admission.mu.Lock()
	s, err := client.admission.slot(client.bootstrap.Handle())
	if err != nil {
		t.Fatal(err)
	}
	open, digest := s.header, s.digest
	client.admission.mu.Unlock()
	wire, err := encodeOpenOutcome(make([]byte, 256), open, digest, true, 16384, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.maintenance.Write(ctx, protocolv4.FrameStreamAck, wire); err != nil {
		t.Fatal(err)
	}
	r, err := client.receiver.Read(ctx, &server.control)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	if err = client.admission.ApplyOutcome(r); !errors.Is(err, ErrOpenAssociation) {
		t.Fatal("bootstrap accepted dynamic outcome", err)
	}
}

func TestBootstrapUnmaterializedRetirementKeepsOriginalProof(t *testing.T) {
	ctx := context.Background()
	client, server := newBootstrapPair(t, protocolv4.DHProfileX25519, "services")
	client.complete(t, server)
	server.complete(t, client)
	deliver := func(from, to *bootstrapEndpoint) {
		t.Helper()
		r, err := to.receiver.Read(ctx, &from.control)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Release()
		if err = to.admission.ApplyMaintenance(r); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []*bootstrapEndpoint{client, server} {
		if err := e.admission.Cancel(e.bootstrap.Handle()); err != nil {
			t.Fatal(err)
		}
		if _, err := e.admission.PublishStopped(ctx, e.bootstrap.Handle(), e.maintenance); err != nil {
			t.Fatal(err)
		}
	}
	deliver(client, server)
	deliver(server, client)
	for _, e := range []*bootstrapEndpoint{client, server} {
		if _, err := e.admission.PublishDrained(ctx, e.bootstrap.Handle(), e.maintenance); err != nil {
			t.Fatal(err)
		}
	}
	deliver(client, server)
	deliver(server, client)
	cr, sr := testRetirement(t, client.openEndpoint, client.maintenance), testRetirement(t, server.openEndpoint, server.maintenance)
	if _, err := cr.Start(ctx, 1, streamTestDeadline(t, cr.admission.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server.openEndpoint, sr, client.control.Bytes())
	client.control.Reset()
	if _, err := sr.Acknowledge(ctx); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, client.openEndpoint, cr, server.control.Bytes())
	server.control.Reset()
	for _, e := range []*bootstrapEndpoint{client, server} {
		if e.admission.Usage().PositiveProofs != 1 || !e.admission.isStable(1) {
			t.Fatal("retirement erased original cleanup responsibility")
		}
		if err := e.admission.CleanupStream(ctx, e.bootstrap.Handle()); err != nil {
			t.Fatal(err)
		}
		if err := e.admission.CarrierClosed(e.bootstrap.Handle()); err != nil {
			t.Fatal(err)
		}
		if e.admission.Usage().PositiveProofs != 0 || e.pool.Outstanding() != 0 {
			t.Fatal("actual cleanup retained proof/promise")
		}
	}
	if err := client.bootstrap.BindLocalCarrier(client.carrier, &client.stream); err == nil {
		t.Fatal("late native result revived stable bootstrap")
	}
	if err := client.engine.OpenLocalScope(1); !errors.Is(err, cryptov4.ErrScope) {
		t.Fatal("retired bootstrap reused ID", err)
	}
}

func TestBootstrapStopBeforeBindingRevokesLateNativeResult(t *testing.T) {
	client, server := newBootstrapPair(t, protocolv4.DHProfileX25519, "execution")
	client.complete(t, server)
	server.complete(t, client)
	if err := client.admission.Cancel(client.bootstrap.Handle()); err != nil {
		t.Fatal(err)
	}
	if err := client.bootstrap.BindLocalCarrier(client.carrier, &client.stream); err == nil {
		t.Fatal("late native handle rebound stopped scope")
	}
	slot, err := client.admission.slot(client.bootstrap.Handle())
	if err != nil {
		t.Fatal(err)
	}
	terminal, fixed := slot.flow.send.Terminal()
	if !fixed || terminal != (TerminalTuple{}) {
		t.Fatal("unsubmitted prefix fabricated frontier", terminal, fixed)
	}
	if client.admission.Usage().Active != 1 || client.admission.Usage().PositiveProofs != 1 {
		t.Fatal("stop forgot live proof charge")
	}
}

// Err is sampled at RecordWriter admission, after the bootstrap/send operation
// owns its reservation but before the engine ticket. This pauses that original
// caller without introducing a test hook in the runtime or holding any gate.
type beforeTicketContext struct {
	context.Context
	remaining       int
	entered, resume chan struct{}
}

func (c *beforeTicketContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		close(c.entered)
		<-c.resume
	}
	return c.Context.Err()
}

func TestBootstrapPendingPublicationAcrossRekeyAndStop(t *testing.T) {
	for _, operation := range []string{"prefix", "data"} {
		for _, stop := range []bool{false, true} {
			t.Run(operation+"/stop="+map[bool]string{false: "false", true: "true"}[stop], func(t *testing.T) {
				client, server := newBootstrapPair(t, protocolv4.DHProfileP256, "services")
				client.complete(t, server)
				server.complete(t, client)
				if err := client.bootstrap.BindLocalCarrier(client.carrier, &client.stream); err != nil {
					t.Fatal(err)
				}
				ctx := &beforeTicketContext{Context: context.Background(), remaining: 1, entered: make(chan struct{}), resume: make(chan struct{})}
				var resume sync.Once
				defer resume.Do(func() { close(ctx.resume) })
				slot, _ := client.admission.slot(client.bootstrap.Handle())
				if operation == "data" {
					if _, err := client.bootstrap.PublishPrefix(context.Background()); err != nil {
						t.Fatal(err)
					}
					server.bindPrefix(t, client)
					ctx.remaining = 2
				}
				type outcome struct {
					result RecordWriteResult
					err    error
				}
				done := make(chan outcome, 1)
				go func() {
					var r RecordWriteResult
					var err error
					if operation == "prefix" {
						r, err = client.bootstrap.PublishPrefix(ctx)
					} else {
						r, err = slot.flow.send.Write(ctx, []byte("queued"), false)
					}
					done <- outcome{r, err}
				}()
				<-ctx.entered
				if stop {
					slot.flow.send.Stop()
					terminal, ok := slot.flow.send.Terminal()
					want := uint64(0)
					if operation == "data" {
						want = 1
					}
					if !ok || terminal != (TerminalTuple{NextSequence: want}) {
						t.Fatal("no-ticket work blocked original terminal", terminal, ok)
					}
				} else {
					cx, sx := exchange(t, client.openEndpoint), exchange(t, server.openEndpoint)
					if _, err := cx.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					exchangeFlight(t, client.openEndpoint, server.openEndpoint, sx)
					exchangeProgress(t, sx)
					exchangeFlight(t, server.openEndpoint, client.openEndpoint, cx)
					exchangeProgress(t, cx)
					exchangeFlight(t, client.openEndpoint, server.openEndpoint, sx)
					exchangeProgress(t, sx)
					exchangeFlight(t, server.openEndpoint, client.openEndpoint, cx)
				}
				resume.Do(func() { close(ctx.resume) })
				got := <-done
				if stop {
					if got.err == nil || got.result.Submitted || client.stream.Len() != 0 {
						t.Fatal("late ticket escaped STOP", got)
					}
					if err := slot.flow.send.WaitCleanup(context.Background()); err != nil {
						t.Fatal(err)
					}
					return
				}
				if got.err != nil || !got.result.Complete || got.result.Header.Epoch != 1 || got.result.Header.Sequence != 0 {
					t.Fatal("queued work retained obsolete epoch", got)
				}
				if operation == "prefix" {
					server.bindPrefix(t, client)
				} else {
					r, err := server.bootstrap.reader.Read(context.Background(), &client.stream)
					if err != nil {
						t.Fatal(err)
					}
					err = server.admission.ApplyData(server.bootstrap.Handle(), server.carrier, r)
					r.Release()
					if err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestBootstrapTransportProfileKeepsDynamicScopeOne(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	if _, err := client.admission.PrepareBootstrap(BootstrapReservation{}); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("transport installed fixed bootstrap", err)
	}
	local, pending, _, _ := startTestOpen(t, client, server, 16)
	if local.Scope() != 1 || pending.Scope() != 1 || server.admission.Usage().Pending != 1 {
		t.Fatal("transport lost its ordinary dynamic scope", local.Scope(), pending.Scope())
	}
	if _, err := server.admission.Decide(context.Background(), pending, BusinessStream, "", server.reservation(new(bytes.Buffer), 16), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	if _, err := client.admission.Flow(local); err != nil {
		t.Fatal(err)
	}
}
