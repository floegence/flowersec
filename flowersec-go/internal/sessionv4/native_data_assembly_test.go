package sessionv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type nativeAssemblyFixture struct {
	root         *resourcev4.Root
	pool         *ReceivePool
	client, peer *cryptov4.Engine
	receiver     *RecordReceiver
	flows        [2]*ReceiveFlow
	assemblies   [2]*NativeDataAssembly
	writers      [2]*RecordWriter
	wire         [2]bytes.Buffer
	serial       uint64
}

func newNativeAssemblyFixture(t *testing.T, capacity uint64) *nativeAssemblyFixture {
	t.Helper()
	f := &nativeAssemblyFixture{client: ioEngine(t, protocolv4.ClientToServer), peer: ioEngine(t, protocolv4.ServerToClient)}
	for _, e := range []*cryptov4.Engine{f.client, f.peer} {
		if err := e.OpenScope(3); err != nil {
			t.Fatal(err)
		}
	}
	decode := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 2048}}
	poolCharge, _ := ReceivePoolCharge(2*capacity, 2)
	receiverCharge, _ := RecordReceiverCharge(4096, 128, decode)
	assemblyCharge, _ := NativeDataAssemblyCharge(1, protocolv4.ClientToServer, protocolv4.DHProfileX25519, 4096)
	limit, _ := poolCharge.Add(receiverCharge)
	for range 2 {
		limit, _ = limit.Add(assemblyCharge)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 4, ReferenceSlots: 8, Limit: limit}
	metadata, _ := resourcev4.BackingBytes(config)
	config.Limit[resourcev4.SDKBytes] += metadata
	var err error
	f.root, err = resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	f.pool, err = NewReceivePool(2*capacity, 2*capacity, 2, f.reserve(t, poolCharge))
	if err != nil {
		t.Fatal(err)
	}
	f.receiver, err = NewRecordReceiver(f.peer, protocolv4.ClientToServer, 4096, 128, decode, f.reserve(t, receiverCharge))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		scope := uint64(2*i + 1)
		f.flows[i], err = NewReceiveFlow(f.pool, scope, protocolv4.ClientToServer, capacity, TerminalTuple{}, capacity)
		if err != nil {
			t.Fatal(err)
		}
		f.flows[i].engine = f.peer // Trusted, accepted direction in this focused fixture.
		f.assemblies[i], err = newNativeDataAssembly(f.flows[i], f.reserve(t, assemblyCharge))
		if err != nil {
			t.Fatal(err)
		}
		f.assemblies[i].phase = nativeDataIdle
		f.writers[i], err = NewRecordWriter(f.client, scope, &f.wire[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.pool.Close()
		for i, assembly := range f.assemblies {
			assembly.Close()
			if err := assembly.retire(); err != nil {
				t.Error("actual native reader/authentication still running", err)
			}
			f.flows[i].Fence()
			if err := f.flows[i].Cleanup(); err != nil {
				t.Error("native receive backing not cleaned", err)
			}
			f.writers[i].Close()
		}
		f.receiver.Close()
		if err := f.receiver.retire(); err != nil || f.root.Snapshot().Reservations != 0 {
			t.Error("original native reservation leaked", err, f.root.Snapshot().Reservations)
		}
		f.root.Close()
	})
	return f
}

func (f *nativeAssemblyFixture) reserve(t *testing.T, charge resourcev4.Vector) resourcev4.Reference {
	t.Helper()
	f.serial++
	var id [16]byte
	binary.BigEndian.PutUint64(id[:], f.serial)
	ref, err := f.root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: id, Backing: id, Kind: 1}, charge)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func (f *nativeAssemblyFixture) data(t *testing.T, i int, offset uint64, fin bool, data []byte) []byte {
	t.Helper()
	f.wire[i].Reset()
	if _, err := f.writers[i].WriteData(context.Background(), protocolv4.ClientToServer, offset, fin, data, len(data)+128); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(f.wire[i].Bytes())
}

func (f *nativeAssemblyFixture) accept(t *testing.T, i int, wire []byte) {
	t.Helper()
	if err := f.assemblies[i].Read(context.Background(), bytes.NewReader(wire)); err != nil {
		t.Fatal(err)
	}
	if err := f.assemblies[i].Authenticate(context.Background(), f.receiver); err != nil {
		t.Fatal(err)
	}
}

// The held call writes into the original receive ring after cancellation as a
// real provider is allowed to do until its call has actually returned.
type nativeHeldReader struct {
	source           *bytes.Reader
	before           int
	entered, release chan struct{}
	once             sync.Once
}

func (r *nativeHeldReader) Read(p []byte) (int, error) {
	if r.before > 0 {
		p = p[:min(len(p), r.before)]
		n, err := r.source.Read(p)
		r.before -= n
		return n, err
	}
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return r.source.Read(p)
}

func holdNativeRead(t *testing.T, x *NativeDataAssembly, wire []byte) (func(), <-chan error) {
	t.Helper()
	reader := &nativeHeldReader{source: bytes.NewReader(wire), before: len(x.header), entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(reader.release) }) }
	t.Cleanup(unblock)
	done := make(chan error, 1)
	go func() { done <- x.Read(context.Background(), reader) }()
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("native provider did not enter promised ring")
	}
	return unblock, done
}

func TestNativeAssemblyPartialDirectionDoesNotHoldSharedAuthentication(t *testing.T) {
	f := newNativeAssemblyFixture(t, 512)
	a := f.data(t, 0, 0, false, bytes.Repeat([]byte("a"), 300))
	b := f.data(t, 1, 0, true, []byte("healthy"))
	unblock, done := holdNativeRead(t, f.assemblies[0], a)
	f.accept(t, 1, b)
	var dst [512]byte
	if n, terminal, err := f.flows[1].TryRead(dst[:]); n != 7 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(dst[:n]) != "healthy" {
		t.Fatal("half frame blocked or corrupted healthy direction", n, terminal, err)
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := f.assemblies[0].Authenticate(context.Background(), f.receiver); err != nil {
		t.Fatal(err)
	}
	if n, _, err := f.flows[0].TryRead(dst[:]); n != 300 || err != nil || !bytes.Equal(dst[:n], bytes.Repeat([]byte("a"), 300)) {
		t.Fatal("original candidate lost", n, err)
	}
}

func TestNativeAssemblyRingWrapPreservesUnreadPlaintext(t *testing.T) {
	f := newNativeAssemblyFixture(t, 512)
	f.accept(t, 0, f.data(t, 0, 0, false, bytes.Repeat([]byte("a"), 400)))
	var dst [512]byte
	if n, _, err := f.flows[0].TryRead(dst[:350]); n != 350 || err != nil {
		t.Fatal(n, err)
	}
	if err := f.flows[0].Grant(862); err != nil {
		t.Fatal(err)
	}
	unblock, done := holdNativeRead(t, f.assemblies[0], f.data(t, 0, 400, true, bytes.Repeat([]byte("b"), 300)))
	if n, _, err := f.flows[0].TryRead(dst[:]); n != 50 || err != nil || !bytes.Equal(dst[:n], bytes.Repeat([]byte("a"), 50)) {
		t.Fatal("ciphertext overlapped unread plaintext", n, err)
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := f.assemblies[0].Authenticate(context.Background(), f.receiver); err != nil {
		t.Fatal(err)
	}
	f.assemblies[0].Close()
	if n, terminal, err := f.flows[0].TryRead(dst[:]); n != 300 || terminal != protocolv4.V4ReadTerminalEof || err != nil || !bytes.Equal(dst[:n], bytes.Repeat([]byte("b"), 300)) {
		t.Fatal("input cleanup erased committed plaintext/EOF", n, terminal, err)
	}
}

func TestNativeAssemblyCloseRetainsActualProviderBacking(t *testing.T) {
	for _, rootClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "direction", true: "root"}[rootClose], func(t *testing.T) {
			f := newNativeAssemblyFixture(t, 512)
			x := f.assemblies[0]
			unblock, done := holdNativeRead(t, x, f.data(t, 0, 0, false, bytes.Repeat([]byte("x"), 300)))
			before := f.root.Snapshot().Charged
			if rootClose {
				f.root.Close()
			}
			x.Close()
			f.pool.Close()
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if err := x.WaitCleanup(canceled); !errors.Is(err, context.Canceled) || f.root.Snapshot().Charged != before {
				t.Fatal("cancellation refunded a real provider tail", err)
			}
			if err := f.flows[0].Cleanup(); !errors.Is(err, ErrReadInProgress) {
				t.Fatal("receive backing reclaimed during provider write", err)
			}
			if err := f.flows[0].releaseUnpublished(false); !errors.Is(err, ErrReadInProgress) {
				t.Fatal("unpublished cleanup bypassed native alias", err)
			}
			if err := x.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
				t.Fatal("native owner retired before actual return", err)
			}
			unblock()
			if err := <-done; !errors.Is(err, ErrFlowClosed) {
				t.Fatal("closed native direction revived", err)
			}
			if err := x.WaitCleanup(context.Background()); err != nil || f.root.Snapshot().Charged != before {
				t.Fatal("cleanup refunded unretired metadata", err)
			}
			observed, _, _, _ := f.flows[0].Snapshot()
			if observed != (TerminalTuple{}) {
				t.Fatal("late input advanced frontier", observed)
			}
		})
	}
}

func TestNativeAssemblyNoCapacityRetainsOriginalCandidate(t *testing.T) {
	for _, crypto := range []bool{false, true} {
		t.Run(map[bool]string{false: "receiver", true: "crypto"}[crypto], func(t *testing.T) {
			f := newNativeAssemblyFixture(t, 512)
			x := f.assemblies[0]
			if err := x.Read(context.Background(), bytes.NewReader(f.data(t, 0, 0, true, []byte("once")))); err != nil {
				t.Fatal(err)
			}
			var release func()
			if crypto {
				a, err := f.peer.Seal(protocolv4.FrameStreamData, 1, nil)
				if err != nil {
					t.Fatal(err)
				}
				b, err := f.peer.Seal(protocolv4.FrameStreamData, 3, nil)
				if err != nil {
					t.Fatal(err)
				}
				release = func() { a.Release(); b.Release() }
			} else {
				if err := f.receiver.begin(context.Background()); err != nil {
					t.Fatal(err)
				}
				release = f.receiver.finish
			}
			if err := x.Authenticate(context.Background(), f.receiver); !errors.Is(err, cryptov4.ErrCapacity) || x.phase != nativeDataReady {
				release()
				t.Fatal("no-attempt refusal discarded candidate", err)
			}
			release()
			if err := x.Authenticate(context.Background(), f.receiver); err != nil {
				t.Fatal(err)
			}
			observed, _, _, _ := f.flows[0].Snapshot()
			if observed != (TerminalTuple{NextSequence: 1, Offset: 4}) {
				t.Fatal("candidate committed more than once", observed)
			}
		})
	}
}

func TestNativeAssemblyRejectsForeignScopeBeforeKeyUse(t *testing.T) {
	f := newNativeAssemblyFixture(t, 512)
	wire := f.data(t, 1, 0, true, []byte("original scope"))
	if err := f.assemblies[0].Read(context.Background(), bytes.NewReader(wire)); err != nil {
		t.Fatal(err)
	}
	if err := f.assemblies[0].Authenticate(context.Background(), f.receiver); !errors.Is(err, protocolv4.ErrRecordScope) {
		t.Fatal("native association selected foreign key", err)
	}
	f.accept(t, 1, wire) // Its actual direction must still have sequence zero.
}

func TestNativeAssemblyRejectsOversizeBeforeBodyRead(t *testing.T) {
	f := newNativeAssemblyFixture(t, 0)
	wire := f.data(t, 0, 0, false, bytes.Repeat([]byte("x"), 512))
	reader := bytes.NewReader(wire)
	if err := f.assemblies[0].Read(context.Background(), reader); !errors.Is(err, ErrCredit) || reader.Len() != len(wire)-protocolv4.EnvelopePrefixSize {
		t.Fatal("untrusted length read body beyond original promise", err, reader.Len())
	}
	f.accept(t, 1, f.data(t, 1, 0, true, nil))
	if n, terminal, err := f.flows[1].TryRead(make([]byte, 1)); n != 0 || terminal != protocolv4.V4ReadTerminalEof || err != nil {
		t.Fatal("zero-credit empty FIN failed", n, terminal, err)
	}
}

func TestNativeAssemblyReadFailureNeverRestartsPrefix(t *testing.T) {
	f := newNativeAssemblyFixture(t, 512)
	wire := f.data(t, 0, 0, false, []byte("partial"))
	x := f.assemblies[0]
	if err := x.Read(context.Background(), bytes.NewReader(wire[:len(wire)-1])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if err := x.Read(context.Background(), bytes.NewReader(wire)); !errors.Is(err, ErrFlowClosed) {
		t.Fatal("partial frame restarted at a new prefix", err)
	}
}

func TestNativeAssemblyRefusesAuthenticationInAnotherResourceEnvironment(t *testing.T) {
	f := newNativeAssemblyFixture(t, 512)
	x := f.assemblies[0]
	if err := x.Read(context.Background(), bytes.NewReader(f.data(t, 0, 0, true, []byte("original")))); err != nil {
		t.Fatal(err)
	}
	foreign, err := newTestRecordReceiver(t, f.peer, protocolv4.ClientToServer, 4096, 128, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Authenticate(context.Background(), foreign); err == nil || x.phase != nativeDataReady {
		t.Fatal("separate resource root substituted for admitted receiver", err)
	}
	if err := x.Authenticate(context.Background(), f.receiver); err != nil {
		t.Fatal(err)
	}
}

type nativeNoProgressReader struct{}

func (nativeNoProgressReader) Read([]byte) (int, error) { return 0, nil }

func TestNativeAssemblyBoundsEveryActualProviderCall(t *testing.T) {
	f := newNativeAssemblyFixture(t, 512)
	input := nativeDataReader{assembly: f.assemblies[0], context: context.Background(), reader: bytes.NewReader(make([]byte, nativeDataReadQuantum*2))}
	if n, err := input.Read(make([]byte, nativeDataReadQuantum*2)); n != nativeDataReadQuantum || err != nil {
		t.Fatal("provider received an unbounded body slice", n, err)
	}
	if err := f.assemblies[1].Read(context.Background(), nativeNoProgressReader{}); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal("zero-progress prefix read could spin indefinitely", err)
	}
}

func TestNativeAssemblyStoppedContractsPromiseWithoutDroppingOriginalRead(t *testing.T) {
	f := newNativeAssemblyFixture(t, 512)
	x, flow := f.assemblies[0], f.flows[0]
	wire := f.data(t, 0, 0, false, bytes.Repeat([]byte("s"), 300))
	unblock, done := holdNativeRead(t, x, wire)
	before := f.root.Snapshot().Charged
	terminal := TerminalTuple{NextSequence: 1, Offset: 300}
	if err := flow.ApplyStopped(terminal); err != nil {
		t.Fatal(err)
	}
	if f.root.Snapshot().Charged != before || f.pool.Outstanding() != 812 {
		t.Fatal("contracted logical promise returned physical native backing")
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal("valid original frame rejected by conservative old claim", err)
	}
	if err := x.Authenticate(context.Background(), f.receiver); err != nil {
		t.Fatal(err)
	}
	if proof, ok := flow.DrainProof(); !ok || proof.Aborted || proof.Observed != terminal || proof.Terminal != terminal {
		t.Fatal("actual final frontier was not authenticated", proof, ok)
	}
	if f.pool.Outstanding() != 512 {
		t.Fatal("abandoned payload promise not settled exactly once")
	}
}

func TestNativeAssemblyIsReservedBeforeOpenAndBoundToAcceptedCarrier(t *testing.T) {
	for _, test := range []struct {
		name, rejection string
		rekey           bool
	}{{name: "accepted"}, {name: "rejected", rejection: "resource_exhausted"}, {name: "early_rekey", rekey: true}} {
		t.Run(test.name, func(t *testing.T) {
			rejection := test.rejection
			client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
			server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
			poolCharge, _ := ReceivePoolCharge(64, 1)
			assemblyCharge, _ := NativeDataAssemblyCharge(1, protocolv4.ServerToClient, protocolv4.DHProfileX25519, 16384)
			decode := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
			receiverCharge, _ := RecordReceiverCharge(16384, 128, decode)
			limit, _ := poolCharge.Add(assemblyCharge)
			limit, _ = limit.Add(receiverCharge)
			config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 3, ReferenceSlots: 8, Limit: limit}
			metadata, _ := resourcev4.BackingBytes(config)
			config.Limit[resourcev4.SDKBytes] += metadata
			root, err := resourcev4.NewRoot(config)
			if err != nil {
				t.Fatal(err)
			}
			owner := &nativeAssemblyFixture{root: root}
			pool, err := NewReceivePool(64, 64, 1, owner.reserve(t, poolCharge))
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := NewRecordReceiver(client.engine, protocolv4.ServerToClient, 16384, 128, decode, owner.reserve(t, receiverCharge))
			if err != nil {
				t.Fatal(err)
			}
			var outbound, reverse bytes.Buffer
			carrier := &CarrierAssociation{}
			reservation := client.reservation(&outbound, 64)
			reservation.Pool = pool
			reservation.NativeReceive = owner.reserve(t, assemblyCharge)
			h, result, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, carrier, reservation, streamTestDeadline(t, client.engine))
			if err != nil || !result.Complete {
				t.Fatal(result, err)
			}
			client.admission.mu.Lock()
			slot, _ := client.admission.slot(h)
			flow := slot.flow
			client.admission.mu.Unlock()
			x := flow.nativeReceive
			if x == nil || x.phase != nativeDataPrepared || len(x.header) == 0 || root.Snapshot().Reservations != 3 {
				t.Fatal("OPEN published before original native backing existed")
			}
			if _, err := client.admission.NativeDataAssembly(h, carrier); !errors.Is(err, ErrOpenAssociation) {
				t.Fatal("pending native input was enabled", err)
			}
			r, err := server.receiver.ReceiveOpen(context.Background(), outbound.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			peer, err := server.admission.Hold(r, &CarrierAssociation{}, streamTestDeadline(t, server.engine))
			r.Release()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, rejection, server.reservation(&reverse, 64), server.maintenance); err != nil {
				t.Fatal(err)
			}
			applyTestOutcome(t, server, client)
			if rejection == "" {
				if err := client.admission.ReadNativeData(context.Background(), h, carrier, bytes.NewReader(nil)); !errors.Is(err, cryptov4.ErrConfiguration) || x.phase != nativeDataPrepared || x.closed {
					t.Fatal("missing service changed original prepared native owner", err)
				}
				if _, err := client.admission.NativeDataAssembly(h, &CarrierAssociation{}); !errors.Is(err, ErrOpenAssociation) {
					t.Fatal("foreign native association admitted", err)
				}
				actual, err := client.admission.NativeDataAssembly(h, carrier)
				if err != nil || actual != x || root.Snapshot().Reservations != 3 {
					t.Fatal("accepted did not reuse original prepared backing", err)
				}
				if _, err := client.admission.NativeDataAssembly(h, carrier); !errors.Is(err, cryptov4.ErrTransition) {
					t.Fatal("two native readers attached to one direction", err)
				}
				peerFlow, err := server.admission.Flow(peer)
				if err != nil {
					t.Fatal(err)
				}
				var clientExchange *RekeyExchange
				if test.rekey {
					clientExchange = exchange(t, client)
					serverExchange := exchange(t, server)
					if _, err := clientExchange.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					exchangeFlight(t, client, server, serverExchange)
					exchangeProgress(t, serverExchange)
					exchangeFlight(t, server, client, clientExchange)
					exchangeProgress(t, clientExchange)
					exchangeFlight(t, client, server, serverExchange)
					exchangeProgress(t, serverExchange)
				}
				if _, err := peerFlow.send.writer.WriteData(context.Background(), protocolv4.ServerToClient, 0, true, []byte("native"), 128); err != nil {
					t.Fatal(err)
				}
				if err := x.Read(context.Background(), &reverse); err != nil {
					t.Fatal(err)
				}
				if test.rekey {
					if err := x.Authenticate(context.Background(), receiver); !errors.Is(err, cryptov4.ErrInputPending) || x.phase != nativeDataReady || receiver.active {
						t.Fatal("early native DATA failed or held full authentication slot", err)
					}
					if observed, _, _, _ := flow.receive.Snapshot(); observed != (TerminalTuple{}) {
						t.Fatal("future candidate advanced original frontier before ACK", observed)
					}
					exchangeFlight(t, server, client, clientExchange)
				}
				if err := x.Authenticate(context.Background(), receiver); err != nil {
					t.Fatal(err)
				}
				var output [64]byte
				if n, terminal, err := flow.receive.TryRead(output[:]); n != 6 || err != nil || terminal != protocolv4.V4ReadTerminalEof || string(output[:n]) != "native" {
					t.Fatal(n, terminal, err)
				}
			} else if !x.cleaned || root.Snapshot().Reservations != 2 {
				t.Fatal("rejected OPEN retained unpublished native preparation")
			}
			client.admission.Close()
			if err := client.admission.CleanupStream(context.Background(), h); err != nil {
				t.Fatal(err)
			}
			if err := x.retire(); err != nil {
				t.Fatal(err)
			}
			if err := flow.send.retire(); err != nil {
				t.Fatal(err)
			}
			receiver.Close()
			if err := receiver.retire(); err != nil || root.Snapshot().Reservations != 0 {
				t.Fatal("real OPEN native cleanup leaked backing", err, root.Snapshot())
			}
			root.Close()
		})
	}
}
