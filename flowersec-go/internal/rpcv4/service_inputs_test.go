package rpcv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func installServiceInputs(t *testing.T, f *rpcFixture, maxCapture uint32) *ServiceInputs {
	t.Helper()
	var buffer [8192]byte
	count, err := f.contract.CopyCanonical(buffer[:])
	if err != nil {
		t.Fatal(err)
	}
	config := ContractRoutesConfig{Methods: []MethodRoutes{{Contracts: [][]byte{buffer[:count]}}}, ContractNodes: 2048, RuntimeBytes: 4096}
	charge, err := ContractRoutesCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewContractRoutes(config, f.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	c := ServiceInputsConfig{GeneralOutstanding: f.n.config.Session.Limits().RPCMaxGeneralOutstanding, MaxCaptureBytes: maxCapture, InputRuntimeBytes: 4096, HashRuntimeBytes: 512, RuntimeBytes: 4096, Root: f.root, Owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{31}, Backing: [16]byte{32}, Kind: 2}}
	charge, err = ServiceInputsCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := f.n.NewServiceInputs(routes, c, f.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	f.r.admission = admission
	t.Cleanup(func() { admission.Close(); routes.Close() })
	return admission
}

func assertRPCSDKResult(t *testing.T, c *Completion, code byte) {
	t.Helper()
	result, err := c.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	borrow, err := result.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	body, h, err := borrow.Bytes()
	if err != nil || !h.IsSDKError() || !bytes.Equal(body, []byte{0xa1, 0, code}) {
		t.Fatal(body, h, err)
	}
}

// v4.go_rpc_services.protected_inputs
func TestServiceInputsDiscardDoesNotBlockOtherCapturedRequests(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 33000)
	h, contract, wire := inputFixture(t, true, payload)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 2), newRPCFixture(t, contract, 2)
	admission := installServiceInputs(t, b, 16)
	_, completion, _ := a.start(h, wire, payload)
	pumpRPC(t, a, b) // The refusal is still private while input is partial.
	if ok, err := b.p.Step(context.Background()); ok || err != nil {
		t.Fatal("early refusal", ok, err)
	}
	small, smallContract, smallWire := inputFixture(t, true, nil)
	defer smallContract.Release()
	a.start(small, smallWire, nil)
	// Fair publication interleaves the captured empty request with discarded DATA.
	for range 4 {
		pumpRPC(t, a, b)
	}
	ticket := takeRPCRequest(t, b)
	if b.n.slots[incoming][ticket.index].header != small {
		t.Fatal("discard escaped into dispatch")
	}
	admission.mu.Lock()
	active := admission.active
	admission.mu.Unlock()
	if active != 0 {
		t.Fatal("completed discard retained collector", active)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	assertRPCSDKResult(t, completion, 5)
}

func TestServiceInputsProtectedDiscardSurvivesExhaustedRootSlots(t *testing.T) {
	h, contract, wire := inputFixture(t, true, []byte("abc"))
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	installServiceInputs(t, b, 1048576)
	var occupied []resourcev4.Reference
	for i := uint64(1); ; i++ {
		owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{44, byte(i)}, Backing: [16]byte{45, byte(i)}, Kind: 3}
		ref, err := b.root.Reserve(owner, resourcev4.Vector{resourcev4.Items: 1})
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		occupied = append(occupied, ref)
	}
	defer func() {
		for _, ref := range occupied {
			ref.Release()
		}
	}()
	_, completion, _ := a.start(h, wire, []byte("abc"))
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	if _, _, err := b.r.NextRequest(); !errors.Is(err, ErrCapacity) {
		t.Fatal("unreserved input was dispatched", err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	assertRPCSDKResult(t, completion, 5)
}

func TestServiceInputsZeroResponseLimitRefusalVerifiesExecutionDigest(t *testing.T) {
	for _, execution := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "execution"}[execution], func(t *testing.T) {
			h, contract, wire := inputFixtureWithLimit(t, execution, []byte("abc"), 0)
			defer contract.Release()
			a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
			installServiceInputs(t, b, 1048576)
			_, completion, _ := a.start(h, wire, []byte("abc"))
			pumpRPC(t, a, b)
			pumpRPC(t, a, b)
			ticket := takeRPCRequest(t, b)
			if err := b.p.QueueRefusal(ticket, "service_unavailable"); err != nil {
				t.Fatal(err)
			}
			pumpRPC(t, b, a)
			pumpRPC(t, b, a)
			assertRPCSDKResult(t, completion, 10)
		})
	}
}

// v4.go_rpc_services.refusal_integrity
func TestServiceInputsUnknownDigestIsRefusalOnlyAndNotVerified(t *testing.T) {
	h, contract, _ := inputFixture(t, true, []byte("abc"))
	defer contract.Release()
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	fields := h.Fields()
	fields.ServiceContractDigest[0] ^= 1
	fields.RequestDigest[0] ^= 1
	var buffer [512]byte
	count, h, err := codec.Encode(buffer[:], h.Kind(), fields)
	if err != nil {
		t.Fatal(err)
	}
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	installServiceInputs(t, b, 1048576)
	_, completion, _ := a.start(h, buffer[:count], []byte("abc"))
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	b.n.mu.Lock()
	state := b.n.slots[incoming][0].inputState
	b.n.mu.Unlock()
	if state != InputRejected {
		t.Fatal("unknown digest claimed complete execution integrity", state)
	}
	if _, _, err := b.r.NextRequest(); !errors.Is(err, ErrCapacity) {
		t.Fatal("unknown route dispatched", err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	assertRPCSDKResult(t, completion, 3)
}

func TestServiceInputsInvalidKnownDigestFailsEvenDuringDiscard(t *testing.T) {
	h, contract, _ := inputFixtureWithLimit(t, true, []byte("abc"), 0)
	defer contract.Release()
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	fields := h.Fields()
	fields.RequestDigest[0] ^= 1
	var buffer [512]byte
	count, h, err := codec.Encode(buffer[:], h.Kind(), fields)
	if err != nil {
		t.Fatal(err)
	}
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	installServiceInputs(t, b, 0)
	a.start(h, buffer[:count], []byte("abc"))
	pumpRPC(t, a, b)
	if ok, err := a.p.Step(context.Background()); !ok || err != nil {
		t.Fatal(ok, err)
	}
	a.sink.published = true
	if _, err := b.r.Feed(a.sink.wire); !errors.Is(err, protocolv4.CBORFailure("application_request_digest")) {
		t.Fatal("discard skipped known digest", err)
	}
	if ok, err := b.p.Step(context.Background()); ok || err != nil {
		t.Fatal("invalid input obtained refusal", ok, err)
	}
}

func TestServiceInputsClosureRetainsPartialDiscardUntilActualExit(t *testing.T) {
	h, contract, wire := inputFixture(t, true, []byte("abc"))
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	admission := installServiceInputs(t, b, 0)
	a.start(h, wire, []byte("abc"))
	pumpRPC(t, a, b)
	admission.Close()
	if admission.CleanupComplete() {
		t.Fatal("partial hash owner was refunded")
	}
	pumpRPC(t, a, b)
	if !admission.CleanupComplete() {
		t.Fatal("actual input exit retained protected backing")
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
}

func TestServiceInputsUnsupportedResponseLimitUsesKnownContractHash(t *testing.T) {
	h, contract, wire := inputFixtureWithContractLimit(t, true, []byte("abc"), 1025, true)
	defer contract.Release()
	if err := contract.CheckRequest(h); !errors.Is(err, protocolv4.CBORFailure("application_response_limit")) {
		t.Fatal("fixture must exceed exact contract limit", err)
	}
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	installServiceInputs(t, b, 1048576)
	_, completion, _ := a.start(h, wire, []byte("abc"))
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	assertRPCSDKResult(t, completion, 4)
}

func TestServiceInputsRefusalPartialAbortUsesOriginalSmallConfirmation(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 20000)
	h, contract, wire := inputFixture(t, true, payload)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	admission := installServiceInputs(t, b, 0)
	ticket, _, _ := a.start(h, wire, payload)
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	if _, err := a.p.CancelRequest(ticket); err != nil {
		t.Fatal(err)
	}
	if f := pumpRPC(t, a, b); f.Kind != protocolv4.RPCAbort {
		t.Fatal(f.Kind)
	}
	admission.mu.Lock()
	active := admission.active
	admission.mu.Unlock()
	if active != 0 {
		t.Fatal("ABORT retained hash owner", active)
	}
	if f := pumpRPC(t, b, a); f.Kind != protocolv4.RPCBegin {
		t.Fatal(f.Kind)
	}
	if f := pumpRPC(t, b, a); !bytes.Equal(f.Payload, []byte{0xa1, 0, 1}) {
		t.Fatal("partial rejection became business refusal", f.Payload)
	}
}

func TestServiceInputsCapturedMethodSurvivesRegistryCloseAndBorrow(t *testing.T) {
	h, contract, wire := inputFixture(t, false, []byte("abc"))
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 2), newRPCFixture(t, contract, 2)
	admission := installServiceInputs(t, b, 1048576)
	a.start(h, wire, []byte("abc"))
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	_, input, err := b.r.NextRequest()
	if err != nil {
		t.Fatal(err)
	}
	admission.routes.Close()
	verified, err := input.Take()
	if err != nil {
		t.Fatal(err)
	}
	method, policy, err := verified.OriginalMethod()
	if err != nil || method != 0 || policy.Namespace != "acme/files" || policy.Digest != h.Fields().ServiceContractDigest {
		t.Fatal(method, policy, err)
	}
	borrow, err := verified.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	verified.Close()
	if verified.CleanupComplete() {
		t.Fatal("live application input refunded")
	}
	body, _, err := borrow.Bytes()
	if err != nil || !bytes.Equal(body, []byte("abc")) {
		t.Fatal(body, err)
	}
	borrow.Release()
	if !verified.CleanupComplete() {
		t.Fatal("actual borrower exit retained input")
	}
	_, completion, _ := a.start(h, wire, []byte("abc"))
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	if _, _, err := b.r.NextRequest(); !errors.Is(err, ErrCapacity) {
		t.Fatal("closed registry admitted a new request", err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	assertRPCSDKResult(t, completion, 10)
}
