package rpcv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func takeVerifiedRPCRequest(t *testing.T, f *rpcFixture) (Ticket, *VerifiedInput) {
	t.Helper()
	ticket, input, err := f.r.NextRequest()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	verified, err := input.Take()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(verified.Close)
	return ticket, verified
}
func reserveAcceptedResult(t *testing.T, f *rpcFixture, limit uint32) (resourcev4.Reference, resourcev4.Reference) {
	t.Helper()
	c, err := AcceptedResultCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	s, err := AcceptedResultSourceCharge(limit, 4096)
	if err != nil {
		t.Fatal(err)
	}
	metadata, source := f.reserve(c), f.reserve(s)
	t.Cleanup(metadata.Release)
	t.Cleanup(source.Release)
	return metadata, source
}
func newTestAcceptedResult(t *testing.T, f *rpcFixture, ticket Ticket, input *VerifiedInput, limit uint32) *AcceptedResult {
	t.Helper()
	m, s := reserveAcceptedResult(t, f, limit)
	result, err := f.p.NewAcceptedResult(ticket, input, m, s, 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(result.Close)
	return result
}
func resultWriter(t *testing.T, o *AcceptedResult) *ResponseWriter {
	t.Helper()
	w, err := o.Writer()
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestAcceptedResultTransfersOriginalBackingAndRetainsActualPublisherTail(t *testing.T) {
	for _, execution := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "execution"}[execution], func(t *testing.T) {
			h, contract, wire := inputFixture(t, execution, nil)
			defer contract.Release()
			a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
			inputs := installServiceInputs(t, b, 1024)
			routes := inputs.routes
			_, completion, _ := a.start(h, wire, nil)
			pumpRPC(t, a, b)
			ticket, input := takeVerifiedRPCRequest(t, b)
			o := newTestAcceptedResult(t, b, ticket, input, h.Fields().ResponseLimitBytes)
			original := &o.payload[0]
			w := resultWriter(t, o)
			if _, err := o.Writer(); !errors.Is(err, ErrOwner) {
				t.Fatal("duplicate output capability", err)
			}
			encoded := []byte("result")
			if n, err := w.Write(encoded); n != len(encoded) || err != nil {
				t.Fatal(n, err)
			}
			clear(encoded)
			// Closing the registration does not replace this accepted exact contract.
			inputs.Close()
			routes.Close()
			if routes.CleanupComplete() {
				t.Fatal("accepted contract body refunded")
			}
			pub, err := w.Finalize(0)
			if err != nil {
				t.Fatal(err)
			}
			if &b.n.slots[incoming][ticket.index].message.payload[0] != original {
				t.Fatal("finalize duplicated backing")
			}
			if _, err := w.Write([]byte("late")); !errors.Is(err, ErrClosed) {
				t.Fatal("post-finalize write", err)
			}
			if _, err := w.Finalize(0); !errors.Is(err, ErrClosed) {
				t.Fatal("second publication", err)
			}
			o.Close()
			input.Close()
			if !routes.CleanupComplete() {
				t.Fatal("finished encoder retained route")
			}
			pumpRPC(t, b, a) // BEGIN
			pumpRPC(t, b, a) // Complete DATA accepted, not yet released by original publisher.
			b.sink.published = false
			before := b.root.Snapshot()
			b.p.Close()
			if o.CleanupComplete() || b.root.Snapshot().Charged != before.Charged {
				t.Fatal("close refunded original provider tail")
			}
			if err := b.p.Retire(); !errors.Is(err, ErrCapacity) {
				t.Fatal("retired live provider tail", err)
			}
			b.sink.published = true
			if err := b.p.Retire(); err != nil {
				t.Fatal(err)
			}
			if !o.CleanupComplete() || !pub.Progress().Terminal {
				t.Fatal("actual output cleanup missing")
			}
			result, err := completion.Take()
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			borrow, err := result.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			defer borrow.Release()
			body, response, err := borrow.Bytes()
			if err != nil || !bytes.Equal(body, []byte("result")) || h.MatchResponse(response) != nil {
				t.Fatal(body, err)
			}
		})
	}
}

func TestAcceptedResultRefusesSubstitutedInputAndDuplicateAdmission(t *testing.T) {
	h, contract, wire := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 2), newRPCFixture(t, contract, 2)
	installServiceInputs(t, b, 1024)
	a.start(h, wire, nil)
	pumpRPC(t, a, b)
	first, input := takeVerifiedRPCRequest(t, b)
	a.start(h, wire, nil)
	pumpRPC(t, a, b)
	second, other := takeVerifiedRPCRequest(t, b)
	m, s := reserveAcceptedResult(t, b, 1024)
	before := b.root.Snapshot()
	if _, err := b.p.NewAcceptedResult(first, other, m, s, 4096); !errors.Is(err, ErrAssociation) {
		t.Fatal("equal header replaced original physical input", err)
	}
	if m.Check() != nil || s.Check() != nil || b.root.Snapshot() != before {
		t.Fatal("rejected association moved resources")
	}
	o, err := b.p.NewAcceptedResult(first, input, m, s, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	nextM, nextS := reserveAcceptedResult(t, b, 1024)
	if _, err := b.p.NewAcceptedResult(first, input, nextM, nextS, 4096); !errors.Is(err, ErrOwner) {
		t.Fatal("two accepted result owners", err)
	}
	if err := o.Refuse("service_unavailable"); err != nil {
		t.Fatal(err)
	}
	newer := newTestAcceptedResult(t, b, second, other, 1024)
	if err := newer.Refuse("service_unavailable"); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptedResultResponseLimitIsAtomicAndLeavesFixedRefusal(t *testing.T) {
	for _, limit := range []uint32{0, 3, 1048576} {
		h, contract, wire := inputFixtureWithLimit(t, false, nil, limit)
		a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
		installServiceInputs(t, b, 1024)
		_, completion, _ := a.start(h, wire, nil)
		pumpRPC(t, a, b)
		ticket, input := takeVerifiedRPCRequest(t, b)
		o := newTestAcceptedResult(t, b, ticket, input, limit)
		w := resultWriter(t, o)
		if n, err := w.Write(bytes.Repeat([]byte{7}, int(limit))); n != int(limit) || err != nil {
			t.Fatal(n, err)
		}
		if n, err := w.Write([]byte{8}); n != 0 || !errors.Is(err, ErrResponseLimit) {
			t.Fatal("overflow partially accepted", n, err)
		}
		if _, err := w.Finalize(0); !errors.Is(err, ErrResponseLimit) {
			t.Fatal("overflow became success", err)
		}
		if ok, err := b.p.Step(context.Background()); ok || err != nil {
			t.Fatal("unfinalized prefix leaked", ok, err)
		}
		if err := o.Refuse("resource_exhausted"); err != nil {
			t.Fatal(err)
		}
		o.Close()
		if !o.CleanupComplete() {
			t.Fatal("refusal retained unused output buffer")
		}
		pumpRPC(t, b, a)
		pumpRPC(t, b, a)
		assertRPCSDKResult(t, completion, 5)
		contract.Release()
	}
}

func TestAcceptedResultAuthenticatedStopFencesOnlyOutput(t *testing.T) {
	h, contract, wire := inputFixture(t, true, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	installServiceInputs(t, b, 1024)
	outgoing, _, _ := a.start(h, wire, nil)
	pumpRPC(t, a, b)
	ticket, input := takeVerifiedRPCRequest(t, b)
	o := newTestAcceptedResult(t, b, ticket, input, 1024)
	w := resultWriter(t, o)
	borrow, err := input.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	if _, err := a.p.CancelRequest(outgoing); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, a, b)
	if _, err := w.Write([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatal("STOP did not fence output", err)
	}
	if _, err := w.Finalize(0); !errors.Is(err, ErrClosed) {
		t.Fatal("STOP allowed new response", err)
	}
	if _, _, err := borrow.Bytes(); err != nil {
		t.Fatal("output interest canceled business input", err)
	}
	o.Close()
}

func TestAcceptedResultUnderfundedSourceCannotAdmit(t *testing.T) {
	h, contract, wire := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	installServiceInputs(t, b, 1024)
	a.start(h, wire, nil)
	pumpRPC(t, a, b)
	ticket, input := takeVerifiedRPCRequest(t, b)
	m, _ := AcceptedResultCharge(4096)
	s, _ := AcceptedResultSourceCharge(1024, 4096)
	s[resourcev4.SDKBytes]--
	metadata, source := b.reserve(m), b.reserve(s)
	defer metadata.Release()
	defer source.Release()
	if _, err := b.p.NewAcceptedResult(ticket, input, metadata, source, 4096); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal(err)
	}
	if b.n.slots[incoming][ticket.index].resultAdmitted {
		t.Fatal("partial response vector admitted")
	}
	o := newTestAcceptedResult(t, b, ticket, input, 1024)
	if err := o.Refuse("service_unavailable"); err != nil {
		t.Fatal(err)
	}
}
