package sessionv4

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// Pause the third original provider read, leaving subsequent wire messages in
// the real WSS connection while QUIC termination and mapping reuse complete.
type relayTailMessages struct {
	*carrierws.Messages
	reads         int
	held, release chan struct{}
}

func (m *relayTailMessages) ReadMessage(ctx context.Context, dst []byte) (int, error) {
	m.reads++
	if m.reads == 3 {
		close(m.held)
		select {
		case <-m.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return m.Messages.ReadMessage(ctx, dst)
}

type relayTailFixture struct {
	ctx         context.Context
	n           *relayNativePair
	messages    *relayTailMessages
	client      *carrierws.Messages
	native      *rawquic.OwnedConnection
	maintenance *rawquic.OwnedStream
	streams     []*rawquic.OwnedStream
	close       func()
}

func newRelayTailFixture(t *testing.T) *relayTailFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	a := admissionIntegration(t, ctx, "preauthorized_pool")
	baseline := a.root.Snapshot()
	var refs []resourcev4.Reference
	reserve := func(charge resourcev4.Vector) resourcev4.Reference {
		t.Helper()
		ref, err := a.root.Reserve(admissionResourceKey(a.owner, uint32(700+len(refs))), charge)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
		return ref
	}
	options := carrierws.Options{MaxMessageBytes: 1024, ReadBufferBytes: 256, WriteBufferBytes: 256,
		HandshakeBytes: 4096, MaxControlsPerSecond: 16, HandshakeTimeout: 5 * time.Second,
		MessageTimeout: 5 * time.Second, RuntimeBytes: 16384, ProviderRuntimeBytes: 65536, ProviderTasks: 4}
	wsCharge, err := carrierws.Charge(options)
	if err != nil {
		t.Fatal(err)
	}
	serverRef := reserve(wsCharge)
	type accepted struct {
		m   *carrierws.Messages
		err error
	}
	ready := make(chan accepted, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, err := carrierws.Upgrade(r.Context(), w, r, carrierws.UpgradeConfig{
			Subprotocol: carrierws.SubprotocolTunnel, CheckPolicy: func(*http.Request) error { return nil },
		}, options, serverRef, a.environment)
		ready <- accepted{m, err}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	clientTLS := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	clientTLS.MinVersion = tls.VersionTLS13
	client, err := carrierws.Dial(ctx, carrierws.DialConfig{
		URL:           "wss" + strings.TrimPrefix(server.URL, "https") + "/flowersec/v4/tunnel",
		RemoteAddress: netip.MustParseAddrPort(server.Listener.Addr().String()),
		Subprotocol:   carrierws.SubprotocolTunnel, TLSConfig: clientTLS,
		CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { return nil },
	}, options, reserve(wsCharge), a.environment)
	if err != nil {
		t.Fatal(err)
	}
	ws := <-ready
	if ws.err != nil {
		t.Fatal(ws.err)
	}
	messages := &relayTailMessages{Messages: ws.m, held: make(chan struct{}), release: make(chan struct{})}

	limits := quicbase.DefaultLimits()
	limits.MaxInboundStreams = 8
	nativeOptions := rawquic.OwnedOptions{Limits: limits, StreamSlots: 8, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	nativeCharge, err := rawquic.OwnedCharge(nativeOptions)
	if err != nil {
		t.Fatal(err)
	}
	quicTLS := server.TLS.Clone()
	quicTLS.NextProtos = []string{rawquic.ALPNTunnel}
	listener, err := rawquic.Listen("127.0.0.1:0", quicTLS, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	clientTLS = clientTLS.Clone()
	clientTLS.NextProtos = []string{rawquic.ALPNTunnel}
	left, err := rawquic.DialOwned(ctx, netip.MustParseAddrPort(listener.Addr().String()), clientTLS,
		nativeOptions, 262144, 128, reserve(nativeCharge), a.environment)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	right, err := rawquic.AcceptOwned(connection, nativeOptions, reserve(nativeCharge), a.environment)
	if err != nil {
		t.Fatal(err)
	}
	interrupt := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = messages.Close()
		_ = left.Close()
		_ = right.Close()
	})
	t.Cleanup(func() { interrupt() })
	maintenance, err := left.OpenMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	peerMaintenance, err := right.AcceptMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var marker [1]byte
	if _, err := io.ReadFull(peerMaintenance, marker[:]); err != nil {
		t.Fatal(err)
	}

	config := RelayMessagePairConfig{Clock: a.trust.clock, PreparationDeadline: a.config.Initial.Deadline,
		MaxEnvelopeBytes: 1024, RuntimeBytes: 4096, MaxPendingNativeMappings: 3,
		MaxResidentNativeMappings: 2, MaxTotalNativeMappings: 8}
	charge, err := RelayMessagePairCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := NewRelayMessagePair(config, reserve(charge), a.environment)
	if err != nil {
		t.Fatal(err)
	}
	n := pair.native
	n.ctx, n.cancel = context.WithCancel(ctx)
	n.connections[1] = left
	if err := left.ClaimSession(pair.reservation); err != nil {
		t.Fatal(err)
	}

	// This isolated forwarding fixture begins after HOP authentication. Its
	// real namespace subscriptions, original deadline, byte meters and provider
	// owners remain active; all mapping creation and retirement use production
	// lane, supervisor and directional I/O code, without prefilled tombstones.
	for side := range 2 {
		meterCharge, err := relayByteBudgetCharge(pair.meterSlots())
		if err != nil {
			t.Fatal(err)
		}
		meter, err := newRelayByteBudget(1<<20, 1<<20, 1024, a.trust.clock, pair.meterSlots(), reserve(meterCharge))
		if err != nil {
			t.Fatal(err)
		}
		prepared := &PreparedCarrier{&preparedCarrier{activated: true, relay: true,
			reservation: reserve(resourcev4.Vector{resourcev4.SDKBytes: 4096}), shared: reserve(resourcev4.Vector{resourcev4.Items: 1}),
			relayBudget: meter, incarnation: [16]byte{byte(side + 1)}}}
		prepared.binding.MessageCarrier = side == 0
		prepared.messageAdapter.owner, prepared.streamAdapter.owner = prepared.preparedCarrier, prepared.preparedCarrier
		if side == 0 {
			prepared.messages = messages
		} else {
			prepared.stream = maintenance
		}
		hop := &RelayHop{prepared: prepared, budget: meter, forwardDeadline: a.config.Initial.Deadline,
			reservation: reserve(resourcev4.Vector{resourcev4.Items: 1}), shared: reserve(resourcev4.Vector{resourcev4.Items: 1}),
			subscriptions: a.trust.subscriptions[side], c: RelayHopConfig{Initial: a.config.Initial}}
		hop.owner.Carrier = prepared.incarnation
		hop.guard.owner = hop
		if err := hop.guard.Check(); err != nil {
			t.Fatal(err)
		}
		n.hops[side] = hop
	}
	pair.running = true
	f := &relayTailFixture{ctx: ctx, n: n, messages: messages, client: client, native: right, maintenance: peerMaintenance, streams: []*rawquic.OwnedStream{maintenance, peerMaintenance}}
	var once sync.Once
	f.close = func() {
		once.Do(func() {
			n.close()
			_ = client.Close()
			_ = messages.Close()
			_ = left.Close()
			_ = right.Close()
			joined := make(chan struct{})
			go func() { n.workers.Wait(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(3 * time.Second):
				t.Error("relay workers did not join")
				return
			}
			for _, hop := range n.hops {
				hop.budget.close()
				hop.budget.mu.Lock()
				pending, users := hop.budget.reserved, hop.budget.users
				hop.budget.mu.Unlock()
				if pending != 0 || users != 0 {
					t.Error("relay byte receipts survived join", pending, users)
				}
			}
			n.mu.Lock()
			for _, slot := range n.slots {
				if slot.active {
					t.Error("mapping survived original worker join")
				}
			}
			for _, queue := range n.queued {
				for _, frame := range queue {
					if frame.used {
						t.Error("ciphertext queue survived original worker join")
					}
				}
			}
			n.mu.Unlock()
			cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
			defer done()
			for _, provider := range []*carrierws.Messages{client, messages.Messages} {
				if err := provider.WaitCleanup(cleanup); err != nil {
					t.Error(err)
				}
				if err := provider.Retire(); err != nil {
					t.Error(err)
				}
			}
			for _, stream := range f.streams {
				_ = stream.Close()
				if err := stream.WaitCleanup(cleanup); err != nil {
					t.Error(err)
				}
				if err := stream.Retire(); err != nil {
					t.Error(err)
				}
			}
			for _, provider := range []*rawquic.OwnedConnection{left, right} {
				if err := provider.WaitCleanup(cleanup); err != nil {
					t.Error(err)
				}
				if err := provider.Retire(); err != nil {
					t.Error(err)
				}
			}
			pair.running = false
			pair.Close()
			for _, ref := range refs {
				ref.Release()
			}
			if got := a.root.Snapshot(); got.Charged != baseline.Charged || got.References != baseline.References {
				t.Error("forwarder/provider resources did not return to baseline", got, baseline)
			}
		})
	}
	t.Cleanup(f.close)
	n.launch(func() { n.readLane(0) })
	return f
}

func relayTailWire(t *testing.T, kind protocolv4.FrameType, scope, sequence uint64) []byte {
	t.Helper()
	wire, err := protocolv4.RecordPrefix(kind, protocolv4.RecordHeader{Scope: scope, Sequence: sequence}, 1, protocolv4.DHProfileX25519, 1016)
	if err != nil {
		t.Fatal(err)
	}
	return append(wire, bytes.Repeat([]byte{byte(sequence)}, 17)...)
}

func relayTailWait(t *testing.T, predicate func() bool) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("original relay transition did not complete")
}

func (f *relayTailFixture) retired(t *testing.T) (int, uint64) {
	t.Helper()
	open := relayTailWire(t, protocolv4.FrameOpenStream, 1, 0)
	if err := f.client.WriteMessage(f.ctx, open); err != nil {
		t.Fatal(err)
	}
	stream, err := f.native.AcceptStream(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.streams = append(f.streams, stream)
	buffer := make([]byte, 1024)
	if size, err := readRelayEnvelope(stream, buffer); err != nil || !bytes.Equal(buffer[:size], open) {
		t.Fatal("original OPEN did not cross native provider", err)
	}
	first := relayTailWire(t, protocolv4.FrameStreamData, 1, 1)
	if err := f.client.WriteMessage(f.ctx, first); err != nil {
		t.Fatal(err)
	}
	if size, err := readRelayEnvelope(stream, buffer); err != nil || !bytes.Equal(buffer[:size], first) {
		t.Fatal("original DATA did not cross native provider", err)
	}
	select {
	case <-f.messages.held:
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	position, generation := -1, uint64(0)
	f.n.mu.Lock()
	for index, slot := range f.n.slots {
		if slot.active && slot.scope == 1 {
			position, generation = index, slot.generation
		}
	}
	f.n.mu.Unlock()
	if position < 0 {
		t.Fatal("original mapping missing")
	}
	for sequence := uint64(2); sequence < 5; sequence++ {
		if err := f.client.WriteMessage(f.ctx, relayTailWire(t, protocolv4.FrameStreamData, 1, sequence)); err != nil {
			t.Fatal(err)
		}
	}
	if err := stream.StopSendingDrained(); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	relayTailWait(t, func() bool { f.n.mu.Lock(); defer f.n.mu.Unlock(); return !f.n.slots[position].active })
	return position, generation
}

func TestRelayNativeProviderBufferedTailsSurviveRetirementAndReuse(t *testing.T) {
	f := newRelayTailFixture(t)
	position, generation := f.retired(t)
	f.n.launch(func() { f.n.accept(1) })
	sibling, err := f.native.OpenStream(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.streams = append(f.streams, sibling)
	open := relayTailWire(t, protocolv4.FrameOpenStream, 2, 0)
	if _, err := sibling.Write(open); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	if size, err := f.client.ReadMessage(f.ctx, buffer); err != nil || !bytes.Equal(buffer[:size], open) {
		t.Fatal("replacement OPEN did not cross WSS", err)
	}
	f.n.mu.Lock()
	reused := f.n.slots[position].active && f.n.slots[position].scope == 2 && f.n.slots[position].generation > generation
	f.n.mu.Unlock()
	if !reused {
		t.Fatal("scenario did not reuse the original mapping position")
	}
	meter := f.n.hops[0].budget
	meter.mu.Lock()
	before := meter.used
	meter.mu.Unlock()
	close(f.messages.release)
	maintenance := relayTailWire(t, protocolv4.FramePing, 0, 0)
	if err := f.client.WriteMessage(f.ctx, maintenance); err != nil {
		t.Fatal(err)
	}
	if size, err := readRelayEnvelope(f.maintenance, buffer); err != nil || !bytes.Equal(buffer[:size], maintenance) {
		t.Fatal("provider tails killed maintenance", err)
	}
	data := relayTailWire(t, protocolv4.FrameStreamData, 2, 1)
	if err := f.client.WriteMessage(f.ctx, data); err != nil {
		t.Fatal(err)
	}
	if size, err := readRelayEnvelope(sibling, buffer); err != nil || !bytes.Equal(buffer[:size], data) {
		t.Fatal("provider tails killed replacement stream", err)
	}
	meter.mu.Lock()
	used := meter.used
	meter.mu.Unlock()
	if used-before != uint64(3*len(data)+len(data)+len(maintenance)) {
		t.Fatal("discarded provider tails escaped original byte meter", used-before)
	}
	select {
	case err := <-f.n.errors:
		t.Fatal("tail failed the pair", err)
	default:
	}
	f.close()
}

func TestRelayNativeProviderTailFactsRejectUnknownDataAndRepeatedOpen(t *testing.T) {
	for _, kind := range []protocolv4.FrameType{protocolv4.FrameStreamData, protocolv4.FrameOpenStream} {
		t.Run(map[protocolv4.FrameType]string{protocolv4.FrameStreamData: "unknown_DATA", protocolv4.FrameOpenStream: "duplicate_OPEN"}[kind], func(t *testing.T) {
			f := newRelayTailFixture(t)
			f.retired(t)
			close(f.messages.release)
			scope := uint64(1)
			if kind == protocolv4.FrameStreamData {
				scope = 99
			}
			if err := f.client.WriteMessage(f.ctx, relayTailWire(t, kind, scope, 0)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-f.n.errors:
				if err != ErrOpenAssociation {
					t.Fatal("unexpected association failure", err)
				}
			case <-f.ctx.Done():
				t.Fatal("unknown DATA/repeated OPEN did not fail pair")
			}
			f.close()
		})
	}
}
