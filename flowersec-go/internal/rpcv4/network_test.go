package rpcv4

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func header(t testing.TB, kind string) protocolv4.ApplicationHeader {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/transport_v4/application_headers.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			Kind, Hex string
			Accept    bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	c, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range corpus.Vectors {
		if v.Kind == kind && v.Accept {
			wire, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			h, err := c.Decode(wire)
			if err != nil {
				t.Fatal(err)
			}
			return h
		}
	}
	t.Fatalf("missing header %s", kind)
	return protocolv4.ApplicationHeader{}
}

func sessionContract(t testing.TB, profile string, k uint64) protocolv4.SessionContract {
	t.Helper()
	app, err := protocolv4.EnumValue("SessionContract", "application_profile", profile)
	if err != nil {
		t.Fatal(err)
	}
	var nested, wire [128]byte
	rekey, err := protocolv4.EncodeMap(nested[:], "RekeyEnvelope", []protocolv4.Field{
		{Name: "burst_rounds", Number: 4}, {Name: "refill_period_ms", Number: 60000}, {Name: "request_start_budget_ms", Number: 30000},
	})
	if err != nil {
		t.Fatal(err)
	}
	fields := []protocolv4.Field{
		{Name: "max_frame", Number: 131072}, {Name: "max_streams", Number: 2048},
		{Name: "max_credit", Number: 1 << 20}, {Name: "idle_duration_ms", Number: 60000},
		{Name: "rekey_envelope", Kind: protocolv4.EncodedMap, Bytes: rekey}, {Name: "application_profile", Number: app},
	}
	if profile != "transport" {
		fields = append(fields, protocolv4.Field{Name: "rpc_max_general_outstanding", Number: k})
	}
	encoded, err := protocolv4.EncodeMap(wire[:], "SessionContract", fields)
	if err != nil {
		t.Fatal(err)
	}
	d, err := protocolv4.NewDecoder(128, 64)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := d.DecodeMap(encoded, "SessionContract", protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	c, err := doc.SessionContract()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type networkFixture struct {
	network   *Network
	root      *resourcev4.Root
	reference resourcev4.Reference
	charge    resourcev4.Vector
}

func newNetworkFixture(t *testing.T, profile string, k uint64) *networkFixture {
	t.Helper()
	q := header(t, "query_contracts_request").Fields()
	config := NetworkConfig{Session: sessionContract(t, profile, k), Query: QueryBinding{q.Type, q.ServiceContractDigest}, RuntimeBytes: 4096}
	charge, err := NetworkCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	c := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 4, ReferenceSlots: 8, Limit: charge}
	backing, err := resourcev4.BackingBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Limit[resourcev4.SDKBytes] += backing
	r, err := resourcev4.NewRoot(c)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := r.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}, charge)
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewNetwork(config, ref)
	if err != nil {
		t.Fatal(err)
	}
	f := &networkFixture{n, r, ref, charge}
	t.Cleanup(func() {
		n.Close()
		if !n.Snapshot().CleanupComplete {
			t.Error("live network owner leaked", n.Snapshot())
		}
		r.Close()
		if !r.Snapshot().CleanupComplete {
			t.Error("resource backing leaked", r.Snapshot())
		}
	})
	return f
}

// v4.go_rpc_network.shared_limits
func TestNetworkSharesSignedGeneralAndQueryAcrossEveryPath(t *testing.T) {
	f := newNetworkFixture(t, "execution", 32)
	n := f.network
	request, stream, query := header(t, "execution_unary_request"), header(t, "execution_stream_request"), header(t, "query_contracts_request")
	var held []Ticket
	defer func() {
		for _, ticket := range held {
			if err := n.Release(ticket); err != nil {
				t.Error(err)
			}
		}
	}()
	for i := 0; i < 32; i++ {
		h := request
		path := Association{Channel: [16]byte{byte(i%8 + 1)}}
		if i >= 16 {
			h = stream
			path.Channel = [16]byte{byte(i + 1)}
		}
		ticket, err := n.ReserveOutgoing(h, path)
		if err != nil {
			t.Fatal(i, err)
		}
		held = append(held, ticket)
		serial := uint64(i + 1)
		if i >= 16 {
			serial = 0
		}
		if err := n.BindOutgoing(ticket, serial); err != nil {
			t.Fatal(err)
		}
		if i < 8 {
			if err := n.Abandon(ticket); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := n.ReserveOutgoing(request, Association{Channel: [16]byte{99}}); !errors.Is(err, ErrCapacity) {
		t.Fatal("new channel multiplied K", err)
	}
	for i := 0; i < 2; i++ {
		ticket, err := n.ReserveOutgoing(query, Association{Channel: [16]byte{1}})
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, ticket)
		if err := n.BindOutgoing(ticket, uint64(100+i)); err != nil {
			t.Fatal(err)
		}
		if err := n.Abandon(ticket); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := n.ReserveOutgoing(query, Association{Channel: [16]byte{99}}); !errors.Is(err, ErrCapacity) {
		t.Fatal("query multiplied Q", err)
	}
	// The peer's reply promises have their own real K+2, never the caller's.
	for i := 0; i < 32; i++ {
		ticket, err := n.AcceptIncoming(request, Association{Channel: [16]byte{1}, Serial: uint64(i + 1)})
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, ticket)
	}
	for i := 0; i < 2; i++ {
		ticket, err := n.AcceptIncoming(query, Association{Channel: [16]byte{1}, Serial: uint64(100 + i)})
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, ticket)
	}
	if _, err := n.AcceptIncoming(request, Association{Channel: [16]byte{2}, Serial: 1}); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	v := n.Snapshot()
	if v.OutgoingGeneral != 32 || v.OutgoingQueries != 2 || v.IncomingGeneral != 32 || v.IncomingQueries != 2 || v.OutgoingFull != 8 || v.OutgoingLate != 10 || v.OutgoingStreaming != 16 || v.IncomingReplies != 34 {
		t.Fatal(v)
	}
}

func TestNetworkTrustedQueryClassificationAndProfile(t *testing.T) {
	f := newNetworkFixture(t, "services", 1)
	n := f.network
	for _, kind := range []string{"execution_unary_request", "execution_stream_request", "execution_notify", "observation_notify", "query_operation_request", "read_result_request", "transient_unary_response", "resume_request"} {
		if _, err := n.ReserveOutgoing(header(t, kind), Association{Channel: [16]byte{1}}); !errors.Is(err, ErrMethod) {
			t.Fatal(kind, err)
		}
	}
	query := header(t, "query_contracts_request")
	n.mu.Lock()
	n.config.Query.Type--
	n.mu.Unlock()
	if _, err := n.ReserveOutgoing(query, Association{Channel: [16]byte{1}}); !errors.Is(err, ErrMethod) {
		t.Fatal("peer kind granted Q", err)
	}
	n.mu.Lock()
	n.config.Query.Type++
	n.config.Query.Contract[0] ^= 1
	n.mu.Unlock()
	if _, err := n.ReserveOutgoing(query, Association{Channel: [16]byte{1}}); !errors.Is(err, ErrMethod) {
		t.Fatal("peer digest granted Q", err)
	}
	for _, kind := range []string{"transient_unary_request", "transient_stream_request"} {
		ticket, err := n.ReserveOutgoing(header(t, kind), Association{Channel: [16]byte{1}})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Release(ticket); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NetworkCharge(NetworkConfig{Session: sessionContract(t, "transport", 0), Query: QueryBinding{1, [32]byte{1}}, RuntimeBytes: 1}); err == nil {
		t.Fatal("transport admitted RPC")
	}
}

func TestNetworkIncomingRefusalRetainsGeneralReplyWithoutGrantingQ(t *testing.T) {
	n := newNetworkFixture(t, "services", 1).network
	for _, kind := range []string{"execution_unary_request", "read_result_request"} {
		h := header(t, kind)
		ticket, err := n.AcceptIncoming(h, Association{Channel: [16]byte{1}, Serial: 1})
		if err != nil {
			t.Fatal("lost profile refusal owner", kind, err)
		}
		if v := n.Snapshot(); v.IncomingGeneral != 1 || v.IncomingQueries != 0 {
			t.Fatal(v)
		}
		if err := n.Release(ticket); err != nil {
			t.Fatal(err)
		}
	}
	query := header(t, "query_contracts_request")
	n.config.Query.Type--
	wrong, err := n.AcceptIncoming(query, Association{Channel: [16]byte{1}, Serial: 2})
	if err != nil {
		t.Fatal("lost unknown-method rejection", err)
	}
	n.config.Query.Type++
	valid, err := n.AcceptIncoming(query, Association{Channel: [16]byte{1}, Serial: 3})
	if err != nil {
		t.Fatal("general refusal stole Q", err)
	}
	if v := n.Snapshot(); v.IncomingGeneral != 1 || v.IncomingQueries != 1 {
		t.Fatal(v)
	}
	if err := n.Release(wrong); err != nil {
		t.Fatal(err)
	}
	if err := n.Release(valid); err != nil {
		t.Fatal(err)
	}
}

// v4.go_rpc_network.original_association
func TestNetworkOriginalBindingLateAndRecycledGenerations(t *testing.T) {
	n := newNetworkFixture(t, "execution", 1).network
	h := header(t, "execution_unary_request")
	path := Association{Channel: [16]byte{1}}
	a, err := n.ReserveOutgoing(h, path)
	if err != nil {
		t.Fatal(err)
	}
	response := header(t, "execution_unary_response")
	if err := n.MatchResponse(a, response, path); err == nil {
		t.Fatal("reserved ticket accepted response")
	}
	if _, err := n.LookupOutgoing(path); err == nil {
		t.Fatal("unsubmitted association exposed")
	}
	if err := n.Abandon(a); err == nil {
		t.Fatal("unsubmitted became late")
	}
	if err := n.BindOutgoing(a, 7); err != nil {
		t.Fatal(err)
	}
	path.Serial = 7
	if err := n.BindOutgoing(a, 8); err == nil {
		t.Fatal("request rebound")
	}
	if err := n.Abandon(a); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := n.Abandon(a); err != nil {
			t.Fatal(err)
		}
	}
	original, bound, err := n.Original(a)
	if err != nil || original != h || bound != path {
		t.Fatal("late lost original", err)
	}
	if err := n.MatchResponse(a, response, path); err != nil {
		t.Fatal(err)
	}
	if found, err := n.LookupOutgoing(path); err != nil || found != a {
		t.Fatal("late lookup lost original", err)
	}
	if _, err := n.LookupIncoming(path); err == nil {
		t.Fatal("direction confused")
	}
	wrong := path
	wrong.Channel[1] = 1
	if err := n.MatchResponse(a, response, wrong); err == nil {
		t.Fatal("old generation/channel accepted")
	}
	if err := n.MatchResponse(a, header(t, "transient_unary_response"), path); err == nil {
		t.Fatal("wrong variant accepted")
	}
	if err := n.Release(a); err != nil {
		t.Fatal(err)
	}
	if _, err := n.LookupOutgoing(path); err == nil {
		t.Fatal("retired serial retained")
	}
	b, err := n.ReserveOutgoing(h, Association{Channel: [16]byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	if b.index != a.index || b.generation == a.generation {
		t.Fatal("fixture did not recycle")
	}
	if err := n.Release(a); !errors.Is(err, ErrOwner) {
		t.Fatal("stale callback freed new owner", err)
	}
	if err := n.BindOutgoing(a, 9); !errors.Is(err, ErrOwner) {
		t.Fatal(err)
	}
	if err := n.Release(b); err != nil {
		t.Fatal(err)
	}
}

// v4.go_rpc_network.actual_cleanup
func TestNetworkCloseRetainsEveryResponsibilityAndReservation(t *testing.T) {
	f := newNetworkFixture(t, "services", 2)
	n := f.network
	h := header(t, "transient_unary_request")
	a, err := n.ReserveOutgoing(h, Association{Channel: [16]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := n.AcceptIncoming(h, Association{Channel: [16]byte{1}, Serial: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.BindOutgoing(a, 1); err != nil {
		t.Fatal(err)
	}
	n.Close()
	f.reference.Release() // The pre-Take alias has no refund right.
	if n.Snapshot().CleanupComplete || f.root.Snapshot().Charged[resourcev4.Items] < f.charge[resourcev4.Items] {
		t.Fatal("logical close refunded responsibility")
	}
	if _, err := n.ReserveOutgoing(h, Association{Channel: [16]byte{2}}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := n.Abandon(a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := n.Original(b); err != nil {
		t.Fatal("closed lost reply binding", err)
	}
	if err := n.Release(a); err != nil {
		t.Fatal(err)
	}
	if n.Snapshot().CleanupComplete {
		t.Fatal("forgot incoming slot")
	}
	if err := n.Release(b); err != nil {
		t.Fatal(err)
	}
	if !n.Snapshot().CleanupComplete || n.slots[0] != nil || n.slots[1] != nil || n.config != (NetworkConfig{}) {
		t.Fatal("retained original graph")
	}
}

func TestNetworkConcurrentAdmissionAndStaleRelease(t *testing.T) {
	n := newNetworkFixture(t, "services", 32).network
	h := header(t, "transient_unary_request")
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				ticket, err := n.ReserveOutgoing(h, Association{Channel: [16]byte{1}})
				if errors.Is(err, ErrCapacity) {
					continue
				}
				if err != nil {
					t.Error(err)
					return
				}
				if err := n.Release(ticket); err != nil {
					t.Error(err)
					return
				}
				if err := n.Release(ticket); !errors.Is(err, ErrOwner) {
					t.Error("stale release", err)
					return
				}
			}
		})
	}
	wg.Wait()
	if v := n.Snapshot(); v.OutgoingGeneral != 0 {
		t.Fatal(v)
	}
}

func TestNetworkAssociationAndGenerationExhaustion(t *testing.T) {
	n := newNetworkFixture(t, "services", 2).network
	h := header(t, "transient_unary_request")
	path := Association{Channel: [16]byte{1}, Serial: 1}
	a, err := n.AcceptIncoming(h, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.AcceptIncoming(h, path); !errors.Is(err, ErrAssociation) {
		t.Fatal("duplicate serial", err)
	}
	if _, err := n.AcceptIncoming(header(t, "transient_stream_request"), Association{Channel: path.Channel}); !errors.Is(err, ErrAssociation) {
		t.Fatal("typed reused ordinary Stream", err)
	}
	if _, err := n.ReserveOutgoing(header(t, "transient_stream_request"), Association{Channel: path.Channel}); !errors.Is(err, ErrAssociation) {
		t.Fatal("opposite direction reused dedicated Stream", err)
	}
	if err := n.Release(a); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	n.slots[outgoing][0].generation = math.MaxUint64
	n.slots[outgoing][1].generation = math.MaxUint64
	n.mu.Unlock()
	if _, err := n.ReserveOutgoing(h, Association{Channel: [16]byte{1}}); !errors.Is(err, ErrCapacity) {
		t.Fatal("generation wrapped", err)
	}
}
