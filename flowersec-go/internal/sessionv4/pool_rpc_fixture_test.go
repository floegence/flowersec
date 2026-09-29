package sessionv4

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// PoolRPCTestHarness exports only test assembly to the external control-adapter
// integration tests. Network, Publisher, Receiver and Completion owners are real;
// the signed Session authorization is the existing component-test authority.
type PoolRPCTestHarness struct {
	f        *serviceDispatchFixture
	Services *RPCServices
	Routes   [2]rpcv4.ContractRoute
}

func NewPoolRPCTestHarness(t *testing.T) *PoolRPCTestHarness {
	t.Helper()
	f, services, _ := shortCallerFixture(t, 4)
	h := &PoolRPCTestHarness{f: f, Services: services}
	var bodies [2][]byte
	definition, err := protocolv4.EncodeMap(make([]byte, 256), "ErrorDefinition", []protocolv4.Field{{Name: "code", Number: 1}, {Name: "schema_revision", Kind: protocolv4.TextString, Text: "pool-result-1"}, {Name: "max_payload_bytes", Number: 524288}, {Name: "schema_digest", Kind: protocolv4.ByteString, Bytes: make([]byte, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	catalog := append([]byte{0x81}, definition...)
	for i, method := range []uint64{41006, 41007} {
		fields := []protocolv4.Field{
			{Name: "service_namespace", Kind: protocolv4.TextString, Text: "pool.control.test"},
			{Name: "type_id", Number: method}, {Name: "call_shape"}, {Name: "unary_semantics"},
			{Name: "request_schema_revision", Kind: protocolv4.TextString, Text: "pool.test"},
			{Name: "response_schema_revision", Kind: protocolv4.TextString, Text: "pool.test"},
			{Name: "response_limit_mode"}, {Name: "min_response_limit_bytes", Number: 524288},
			{Name: "max_response_bytes", Number: 524288}, {Name: "max_message_lifetime_ms", Number: 1000},
			{Name: "max_transient_run_ms", Number: 1000}, {Name: "restart_flush", Kind: protocolv4.Boolean},
			{Name: "request_max_bytes", Number: 524288}, {Name: "application_error_catalog", Kind: protocolv4.EncodedArray, Bytes: catalog},
		}
		var err error
		bodies[i], err = protocolv4.EncodeMap(make([]byte, 512), "ServiceContract", fields)
		if err != nil {
			t.Fatal(err)
		}
	}
	c := rpcv4.ContractRoutesConfig{Methods: []rpcv4.MethodRoutes{{Contracts: [][]byte{bodies[0]}}, {Contracts: [][]byte{bodies[1]}}}, ContractNodes: 256, RuntimeBytes: 4096}
	charge, err := rpcv4.ContractRoutesCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := rpcv4.NewContractRoutes(c, h.Reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	for i, body := range bodies {
		codec, err := protocolv4.NewServiceContractCodec(256)
		if err != nil {
			t.Fatal(err)
		}
		contract, err := codec.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := contract.Policy()
		contract.Release()
		if err != nil {
			t.Fatal(err)
		}
		charge, _ = rpcv4.ContractRouteCharge(4096)
		h.Routes[i], err = routes.Capture(policy.Digest, h.Reserve(t, charge), 4096)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(h.Routes[i].Release)
	}
	return h
}
func (h *PoolRPCTestHarness) Reserve(t *testing.T, charge resourcev4.Vector) resourcev4.Reference {
	t.Helper()
	return h.f.f.reserve(t, 1, charge)
}

func (h *PoolRPCTestHarness) Respond(t *testing.T, serial uint64, payload []byte, holdPublication bool, failed <-chan error, applicationError ...uint32) protocolv4.ApplicationHeader {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var request protocolv4.ApplicationHeader
	for request.Kind() == "" {
		h.Services.mu.Lock()
		for _, invocation := range h.Services.generalCalls {
			if invocation == nil {
				continue
			}
			invocation.mu.Lock()
			if !invocation.preparing && !invocation.cleaned {
				request = invocation.request
			}
			invocation.mu.Unlock()
			if request.Kind() != "" {
				break
			}
		}
		h.Services.mu.Unlock()
		if request.Kind() != "" {
			break
		}
		select {
		case err := <-failed:
			t.Fatal("original RPC failed before publication", err)
		case <-ctx.Done():
			t.Fatal("original RPC was not prepared")
		case <-time.After(time.Millisecond):
		}
	}
	for range 2 {
		if _, err := h.f.publisher.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	h.f.sink.held.Store(holdPublication)
	if len(applicationError) == 0 {
		receiveShortResponse(t, h.f, request, serial, payload)
	} else {
		fields := request.Fields()
		fields.Kind, fields.DeadlineAtMS, fields.AdmissionMode, fields.ResponseLimitBytes = 0, 0, 0, 0
		fields.PayloadBytes, fields.ApplicationErrorCode = uint32(len(payload)), applicationError[0]
		var wire [512]byte
		n, _, err := h.f.codec.Encode(wire[:], "transient_unary_application_error", fields)
		if err != nil {
			t.Fatal(err)
		}
		encoded := make([]byte, len(payload)+1024)
		for _, fragment := range []protocolv4.RPCFragment{{Kind: protocolv4.RPCBegin, Serial: serial, ReplyTo: serial, Header: wire[:n]}, {Kind: protocolv4.RPCData, Serial: serial, Payload: payload}} {
			n, e := protocolv4.EncodeRPCFragment(encoded, fragment)
			if e != nil {
				t.Fatal(e)
			}
			if used, e := h.f.receiver.Feed(encoded[:n]); e != nil || used != n {
				t.Fatal(used, e)
			}
		}
	}
	h.Services.AdvanceCalls()
	return request
}

func (h *PoolRPCTestHarness) Advance(t *testing.T, releasePublication bool) {
	t.Helper()
	if releasePublication {
		h.f.sink.held.Store(false)
		if _, err := h.f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	h.Services.AdvanceCalls()
}
