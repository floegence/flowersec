package sessionv4

import (
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestStreamMessagesSelectedEnvelopeOwnsActualBuffers(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	body := admissionMap(t, "ServiceContract", initialFixture(t, "service_stream_transient"), map[string]protocolv4.Field{"type_id": {Number: 2}})
	contract, err := codec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	defer contract.Release()
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	if definition.Methods[1].Method.Contract != policy.Digest {
		t.Fatal("fixture route identity differs")
	}
	_, authority, err := r.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := timev4.NewDeadline(f.trust.clock, 2000)
	if err != nil {
		t.Fatal(err)
	}
	var previous resourcev4.Vector
	var previousLimit uint32
	for _, limit := range []uint32{policy.MinResponseBytes, 1024, policy.MaxResponseBytes} {
		var wire [512]byte
		_, header, err := f.codec.Encode(wire[:], "transient_stream_request", protocolv4.ApplicationHeaderFields{Type: policy.Type, ServiceContractDigest: policy.Digest, PayloadBytes: 3, DeadlineAtMS: 2000, ResponseLimitBytes: limit})
		if err != nil {
			t.Fatal(err)
		}
		config := StreamMessagesConfig{HardDeadline: deadline, Request: header, RuntimeBytes: 4096}
		charge, err := StreamMessagesCharge(policy, config)
		if err != nil {
			t.Fatal(err)
		}
		if previous != (resourcev4.Vector{}) {
			expected, _ := previous.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(max(limit, 256) - max(previousLimit, 256))})
			if charge != expected {
				t.Fatal("chosen item bytes diverge from actual charge")
			}
		}
		previous, previousLimit = charge, limit
		deliveryCharge, err := protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		delivery, err := authority.ForkDelivery(f.f.reserve(t, 1, deliveryCharge))
		if err != nil {
			t.Fatal(err)
		}
		m, err := prepareStreamMessages(contract, config, f.f.reserve(t, 1, charge), delivery)
		if err != nil {
			delivery.Close(err)
			t.Fatal(err)
		}
		if cap(m.input) != int(max(limit, 256)) || cap(m.output) != 3 {
			t.Fatal("constructed buffers ignored selected envelope", cap(m.input), cap(m.output))
		}
		if err := m.prepareRequestLocked([]byte("req")); err != nil {
			t.Fatal(err)
		}
		m.Close()
		if !m.Status().CleanupComplete {
			t.Fatal("unpublished stream retained buffers")
		}
	}
	// Preparation selects a fresh explicit larger limit without weakening the
	// exact contract; the small default never becomes a new method hard limit.
	op, err := r.prepareStreamingMethod(context.Background(), r.plan.host.core, definition.Methods[1].Method, "test/events", nil, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: policy.MaxResponseBytes, ExplicitResponseLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	if op.owner.header.Fields().ResponseLimitBytes != policy.MaxResponseBytes {
		t.Fatal("legal larger limit was truncated")
	}
}
