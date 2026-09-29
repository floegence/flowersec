package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestEnvironmentResultProtectionPreservesShortResultAtLocalCapacity(t *testing.T) {
	f, r, route := shortCallerFixture(t, 4)
	f, r, route, e := deferredCallerForServiceFixture(t, f, r, route, 2)
	var wire [512]byte
	n, h, err := f.codec.Encode(wire[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: 3, DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	decode := func(_ context.Context, payload []byte) (any, error) { return string(payload), nil }
	ordinary, err := r.BeginDeferredUnary(context.Background(), route, h, wire[:n], []byte("req"), ApplicationResident, decode)
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	before := f.f.root.Snapshot()
	if call, err := r.BeginDeferredUnary(context.Background(), route, h, wire[:n], []byte("req"), ApplicationResident, decode); call != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("ordinary result consumed the protected Environment position", call, err)
	}
	if after := f.f.root.Snapshot(); after != before {
		t.Fatal("rejected local result retained partial backing", before, after)
	}
	short, err := r.BeginDeferredShortUnary(context.Background(), route, h, wire[:n], []byte("req"), decode)
	if err != nil {
		t.Fatal("ordinary result exhaustion stole the short opportunity", err)
	}
	defer short.Close()
	if e.OperationsSnapshot().ActiveResults != 2 || f.network.Snapshot().OutgoingGeneral != 2 {
		t.Fatal("protected result did not use the original tables")
	}
	finishShortResponse(t, f, h, 1, []byte("ordinary"))
	finishShortResponse(t, f, h, 2, []byte("short"))
	r.AdvanceCalls()
	ctx := resultTestContext(t)
	for i, call := range []*UnaryCall{ordinary, short} {
		payload, status, err := call.TakeEncodedResult(ctx)
		if err != nil || !status.Delivered || string(payload) != []string{"ordinary", "short"}[i] {
			t.Fatal(string(payload), status, err)
		}
	}
}

func TestEnvironmentResultProtectionKeepsIndexUntilCompletedOwnerCleanup(t *testing.T) {
	f, r, route := shortCallerFixture(t, 4)
	f, r, route, e := deferredCallerForServiceFixture(t, f, r, route, 1)
	var wire [512]byte
	n, h, err := f.codec.Encode(wire[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: 3, DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	call, err := r.BeginDeferredShortUnary(context.Background(), route, h, wire[:n], []byte("req"), func(_ context.Context, input []byte) (any, error) { return input, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer call.Close()
	position := r.shortResultPosition
	position.close()
	finishShortResponse(t, f, h, 1, []byte("retained"))
	r.AdvanceCalls()
	if _, err := e.protectResult(e.reservation); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("closed declaration refunded completed but undelivered result", err)
	}
	payload, status, err := call.TakeEncodedResult(resultTestContext(t))
	if err != nil || !status.Delivered || string(payload) != "retained" {
		t.Fatal(string(payload), status, err)
	}
	call.Close()
	var replacement environmentResultProtection
	ctx := resultTestContext(t)
	for {
		e.advanceResults()
		replacement, err = e.protectResult(e.reservation)
		if err == nil {
			break
		}
		if !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual result cleanup retained its old index", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	defer replacement.close()
	position.close()
	e.mu.Lock()
	_, err = replacement.slotLocked()
	e.mu.Unlock()
	if err != nil {
		t.Fatal("stale protection closed its replacement", err)
	}
}

func TestControllerHeadroomTransfersOriginalResultPositionOnce(t *testing.T) {
	f, _, _, e := deferredCallerFixture(t)
	position, err := e.protectResult(e.reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer position.close()
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{207}, Backing: [16]byte{207}, Kind: 207}
	request := resourcev4.Request{Owner: owner, Charge: resourcev4.Vector{resourcev4.SDKBytes: 64}}
	h := &sessionHeadroom{count: 1, resultPosition: position}
	defer h.close()
	if err := f.f.root.ReserveBatch([]resourcev4.Request{request}, h.refs[:1]); err != nil {
		t.Fatal(err)
	}
	var refs [1]resourcev4.Reference
	var unprepared sessionAdmissionBatch
	if err := h.claim([]resourcev4.Request{request}, refs[:], &unprepared, resourcev4.Reference{}); !errors.Is(err, cryptov4.ErrConfiguration) || refs[0] != (resourcev4.Reference{}) {
		t.Fatal("unprepared claim consumed original headroom", err)
	}
	batch := sessionAdmissionBatch{rpc: rpcServicesBatch{prepared: true}}
	if err := h.claim([]resourcev4.Request{request}, refs[:], &batch, resourcev4.Reference{}); err != nil {
		t.Fatal(err)
	}
	defer refs[0].Release()
	defer batch.rpc.resultPosition.close()
	h.close()
	e.mu.Lock()
	_, err = batch.rpc.resultPosition.slotLocked()
	e.mu.Unlock()
	if err != nil || batch.rpc.resultPosition != position {
		t.Fatal("original headroom alias closed the adopted result position", err)
	}
	if err := h.claim([]resourcev4.Request{request}, refs[:], &batch, resourcev4.Reference{}); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("headroom was claimed twice", err)
	}
}

func TestEnvironmentResultProtectionBatchDoesNotPartiallyReserve(t *testing.T) {
	f, r, route := shortCallerFixture(t, 4)
	_, _, _, e := deferredCallerForServiceFixture(t, f, r, route, 3)
	before := e.OperationsSnapshot()
	var tooMany [3]environmentResultProtection
	if err := e.protectResults(e.reservation, tooMany[:]); !errors.Is(err, cryptov4.ErrCapacity) || tooMany != ([3]environmentResultProtection{}) || e.OperationsSnapshot() != before {
		t.Fatal("failed result target batch retained a partial claim", err)
	}
	var positions [2]environmentResultProtection
	if err := e.protectResults(e.reservation, positions[:]); err != nil {
		t.Fatal(err)
	}
	for _, position := range positions {
		defer position.close()
	}
	if snapshot := e.OperationsSnapshot(); snapshot.ProtectedResults != 3 || snapshot.ActiveResults != 0 {
		t.Fatal("future positions created active results", snapshot)
	}
	if err := e.protectResults(e.reservation, positions[:]); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("result batch overwrote original caller ownership", err)
	}
	e.Close()
	if snapshot := e.OperationsSnapshot(); snapshot.ProtectedResults != 0 {
		t.Fatal("Environment close retained future result claims", snapshot)
	}
}
