package controlv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type resultTestAccess struct{ denied atomic.Bool }

func (a *resultTestAccess) CheckTopUpAccess(tenant string, source [16]byte) error {
	if a.denied.Load() || tenant != "tenant-1" || source != ([16]byte{1}) {
		return errors.New("permission denied")
	}
	return nil
}
func resultTestConfig() PoolResultDecoderConfig {
	return PoolResultDecoderConfig{Tenant: "tenant-1", Source: [16]byte{1}, ClientStore: ledgerv4.SQLiteIdentity{Authority: "client-1", StoreID: [32]byte{1}, Generation: 1}, Access: &resultTestAccess{}, RuntimeBytes: 4096}
}
func newResultTestDecoder(t *testing.T, c PoolResultDecoderConfig) *PoolResultDecoder {
	t.Helper()
	var limit resourcev4.Vector
	for i := range limit {
		limit[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 4, ReservationSlots: 8, ReferenceSlots: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	reserve := func(id byte, cost resourcev4.Vector) resourcev4.Reference {
		r, e := root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{id}, Backing: [16]byte{id}, Kind: 1}, cost)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(r.Release)
		return r
	}
	cost, err := PoolResultDecoderCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewPoolResultDecoder(c, reserve(1, cost), reserve(2, resourcev4.Vector{resourcev4.SDKBytes: 4096}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if e := d.WaitCleanup(ctx); e != nil {
			t.Error(e)
		}
	})
	return d
}
func testTerminal(t *testing.T, known bool) ledgerv4.TopUpServerSnapshot {
	t.Helper()
	r := protocolv4.TopUpRequestFacts{Tenant: "tenant-1", Source: [16]byte{1}, Pool: [32]byte{2}, Identity: [32]byte{3}, Generation: 1, DeadlineMS: 100, DesiredCount: 1, MaxItemBytes: 65536}
	binary.BigEndian.PutUint64(r.Operation[:8], 1)
	r.Operation[8] = 9
	codec, e := protocolv4.NewTopUpCodec()
	if e != nil {
		t.Fatal(e)
	}
	r.Digest, e = codec.RequestDigest(r)
	if e != nil {
		t.Fatal(e)
	}
	s := ledgerv4.TopUpServerSnapshot{State: ledgerv4.TopUpServerRetired, BindingGeneration: 1, NextSequence: 2, RetiredSequence: 1, Request: r, Terminal: protocolv4.V4TopUpErrorCodeTopUpRequestExpired}
	if known {
		s.Terminal = protocolv4.V4TopUpErrorCodeSourceResetRequired
		s.HighestArtifact, s.RetiredArtifact = 1, 1
		s.Response = protocolv4.TopUpResponseFacts{Operation: r.Operation, Source: r.Source, Tenant: r.Tenant, Generation: 1, Highest: 1, Digest: [32]byte{4}, Count: 1, Entries: [4]protocolv4.TopUpEntryFacts{{Sequence: 1, Generation: 1, ExpiryMS: 200, Material: [32]byte{5}, Identity: r.Identity}}}
	}
	return s
}
func resultTestWire(t *testing.T, method uint32, reply PoolControlReply) []byte {
	t.Helper()
	b := make([]byte, 524288)
	n, e := EncodePoolControlReply(b, method, reply)
	if e != nil {
		t.Fatal(e)
	}
	return b[:n:n]
}

func TestPoolResultTerminalExactBindingAndReleasedAliases(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown-response", true: "known-response"}[known], func(t *testing.T) {
			c := resultTestConfig()
			d := newResultTestDecoder(t, c)
			s := testTerminal(t, known)
			wire := resultTestWire(t, ControlPoolTopUp, PoolControlReply{Code: protocolv4.V4TopUpWireResult(s.Terminal), Terminal: &s})
			r, e := d.DecodePoolControlResult(context.Background(), ControlPoolTopUp, true, wire, nil)
			if e != nil || r.Terminal != s || r.Evidence == nil {
				t.Fatal(r, e)
			}
			defer r.Release()
			clear(wire)
			if e = r.Evidence.CheckTopUpTerminal(c.ClientStore, s.Request, s); e != nil {
				t.Fatal("retained borrowed parser bytes", e)
			}
			wrong := c.ClientStore
			wrong.Generation++
			if e = r.Evidence.CheckTopUpTerminal(wrong, s.Request, s); e == nil {
				t.Fatal("foreign store accepted")
			}
			other := s
			other.RetiredSequence = 0
			if e = r.Evidence.CheckTopUpTerminal(c.ClientStore, s.Request, other); e == nil {
				t.Fatal("altered history accepted")
			}
			wire = resultTestWire(t, ControlPoolTopUp, PoolControlReply{Code: protocolv4.V4TopUpWireResult(s.Terminal), Terminal: &s})
			if _, e = d.DecodePoolControlResult(context.Background(), ControlPoolTopUp, true, wire, nil); !errors.Is(e, ErrBusy) {
				t.Fatal("unbounded receipt owners", e)
			}
			alias := r
			r.Release()
			if e = alias.Evidence.CheckTopUpTerminal(c.ClientStore, s.Request, s); e == nil {
				t.Fatal("released alias accepted")
			}
			next, e := d.DecodePoolControlResult(context.Background(), ControlPoolTopUp, true, wire, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer next.Release()
			alias.Release()
			if e = next.Evidence.CheckTopUpTerminal(c.ClientStore, s.Request, s); e != nil {
				t.Fatal("old alias released new receipt", e)
			}
			c.Access.(*resultTestAccess).denied.Store(true)
			var failure ledgerv4.TopUpFailure
			if e = next.Evidence.CheckTopUpTerminal(wrong, s.Request, other); !errors.As(e, &failure) || failure.Fact.Code != protocolv4.V4TopUpErrorCodePermissionDenied {
				t.Fatal("permission precedence", e)
			}
			c.Access.(*resultTestAccess).denied.Store(false)
			d.Close()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if e = d.WaitCleanup(ctx); !errors.Is(e, context.Canceled) {
				t.Fatal("receipt backing released early", e)
			}
			if e = next.Evidence.CheckTopUpTerminal(c.ClientStore, s.Request, s); !errors.Is(e, resourcev4.ErrClosed) {
				t.Fatal("closed decoder retained authority", e)
			}
			next.Release()
			if e = d.WaitCleanup(context.Background()); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestPoolResultPermanentFenceHasNoInventedHistory(t *testing.T) {
	c := resultTestConfig()
	d := newResultTestDecoder(t, c)
	fence := ledgerv4.TopUpPermanentFenceReceipt{Tenant: c.Tenant, Source: c.Source, Generation: 2}
	b := resultTestWire(t, ControlPoolAck, PoolControlReply{Code: "source_reset_required", Fence: &fence})
	r, e := d.DecodePoolControlResult(context.Background(), ControlPoolAck, true, b, nil)
	if e != nil || r.Evidence != nil || r.Terminal != (ledgerv4.TopUpServerSnapshot{}) || r.FenceEvidence == nil || r.Fence != fence {
		t.Fatal(r, e)
	}
	defer r.Release()
	if e = r.FenceEvidence.CheckTopUpPermanentFence(c.ClientStore, fence); e != nil {
		t.Fatal(e)
	}
	fence.Generation++
	if e = r.FenceEvidence.CheckTopUpPermanentFence(c.ClientStore, fence); e == nil {
		t.Fatal("changed fence accepted")
	}
}

func TestPoolResultSuccessPreservesOriginalBytesAndClosedEnvelope(t *testing.T) {
	c := resultTestConfig()
	d := newResultTestDecoder(t, c)
	ctx := context.Background()
	original := []byte{0xa1, 0x00, 0x01}
	wire := resultTestWire(t, ControlPoolTopUp, PoolControlReply{Code: "replay", Response: original})
	dst := make([]byte, 524288)
	r, e := d.DecodePoolControlResult(ctx, ControlPoolTopUp, false, wire, dst)
	if e != nil || !r.Replay || r.ResponseBytes != len(original) || !bytes.Equal(dst[:r.ResponseBytes], original) {
		t.Fatal(r, e)
	}
	for _, bad := range [][]byte{append(bytes.Clone(wire), 0), append([]byte{0x98, 4}, wire[1:]...), {0xa0}, {0x84, 0xf6, 0x40, 0xf6, 0xf6}} {
		if r, e = d.DecodePoolControlResult(ctx, ControlPoolTopUp, false, bad, dst); e == nil || r.Evidence != nil {
			t.Fatal("malformed envelope", r, e)
		}
	}
	for _, method := range []uint32{ControlPoolAck, 41008} {
		if _, e = d.DecodePoolControlResult(ctx, method, false, wire, dst); e == nil {
			t.Fatal("wrong method accepted")
		}
	}
	if _, e = d.DecodePoolControlResult(ctx, ControlPoolTopUp, true, wire, dst); e == nil {
		t.Fatal("error kind mismatch")
	}
	if _, e = d.DecodePoolControlResult(ctx, ControlPoolTopUp, false, wire, dst[:1]); e == nil {
		t.Fatal("truncated response")
	}
	s := testTerminal(t, false)
	s.Request.Digest[0]++
	wire = resultTestWire(t, ControlPoolTopUp, PoolControlReply{Code: protocolv4.V4TopUpWireResult(s.Terminal), Terminal: &s})
	if _, e = d.DecodePoolControlResult(ctx, ControlPoolTopUp, true, wire, nil); e == nil {
		t.Fatal("request digest mismatch")
	}
	s = testTerminal(t, false)
	s.Request.Source[0]++
	wire = resultTestWire(t, ControlPoolTopUp, PoolControlReply{Code: protocolv4.V4TopUpWireResult(s.Terminal), Terminal: &s})
	if _, e = d.DecodePoolControlResult(ctx, ControlPoolTopUp, true, wire, nil); e == nil {
		t.Fatal("foreign source accepted")
	}
	c.Access.(*resultTestAccess).denied.Store(true)
	_, e = d.DecodePoolControlResult(ctx, ControlPoolAck, false, []byte{0xff}, nil)
	var failure ledgerv4.TopUpFailure
	if !errors.As(e, &failure) || failure.Fact.Code != protocolv4.V4TopUpErrorCodePermissionDenied {
		t.Fatal(e)
	}
}

func TestPoolHTTPSAuthenticatedTerminalReceipt(t *testing.T) {
	c := resultTestConfig()
	d := newResultTestDecoder(t, c)
	s := testTerminal(t, true)
	wire := resultTestWire(t, ControlPoolTopUp, PoolControlReply{Code: protocolv4.V4TopUpWireResult(s.Terminal), Terminal: &s})
	p, _ := testPoolHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", strconv.Itoa(len(wire)))
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write(wire)
	}), d.DecodePoolControlResult)
	r, e := p.TopUp(context.Background(), []byte{0xa0}, make([]byte, 524288))
	if e != nil || r.Evidence == nil || r.Terminal != s {
		t.Fatal("authenticated receipt", r, e)
	}
	defer r.Release()
	if e = r.Evidence.CheckTopUpTerminal(c.ClientStore, s.Request, s); e != nil {
		t.Fatal(e)
	}
	r.Release()
	// An unavailable receipt owner after successful TLS must fail closed.
	d.Close()
	r, e = p.TopUp(context.Background(), []byte{0xa0}, make([]byte, 524288))
	if e == nil || r.Evidence != nil || r.Terminal != (ledgerv4.TopUpServerSnapshot{}) {
		t.Fatal("closed decoder minted evidence", r, e)
	}
}
