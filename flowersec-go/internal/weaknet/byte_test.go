package weaknet

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestByteRelayPreservesPayloadAndModelsOnlyStreamFaithfulEffects(t *testing.T) {
	expected := Counters{
		InputUnits:        3,
		InputBytes:        10,
		OutputUnits:       3,
		OutputBytes:       10,
		DelayUnits:        3,
		JitterUnits:       1,
		RateLimitedUnits:  2,
		OutageUnits:       1,
		FragmentUnits:     5,
		CoalescedUnits:    2,
		BackpressureUnits: 1,
		HalfCloses:        1,
	}
	profile := ByteProfile{
		Phase:             "stream-fidelity",
		Direction:         ServerToClient,
		Seed:              0x5eed,
		Delay:             2 * time.Millisecond,
		JitterScript:      []time.Duration{0, time.Millisecond},
		Rate:              RateLimit{BytesPerSecond: 4, BurstBytes: 4},
		Outages:           []TimedOutage{{Ordinals: OrdinalRange{First: 3, Last: 3}, Duration: 5 * time.Millisecond}},
		FragmentPattern:   []int{2, 3},
		CoalesceBytes:     4,
		BackpressureBytes: 6,
		RequireHalfClose:  true,
		Expected:          &expected,
	}
	relay, err := NewByteRelay(profile)
	if err != nil {
		t.Fatal(err)
	}

	var deliveries []ByteDelivery
	output, err := relay.Write(ByteChunk{At: time.Millisecond, Payload: []byte("abcd")})
	if err != nil {
		t.Fatal(err)
	}
	deliveries = append(deliveries, output...)
	if _, err := relay.Write(ByteChunk{At: 2 * time.Millisecond, Payload: []byte("efgh")}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("backpressure error = %v, want ErrBackpressure", err)
	}
	if err := relay.Acknowledge(4); err != nil {
		t.Fatal(err)
	}
	output, err = relay.Write(ByteChunk{At: 2 * time.Millisecond, Payload: []byte("efgh")})
	if err != nil {
		t.Fatal(err)
	}
	deliveries = append(deliveries, output...)
	output, err = relay.Write(ByteChunk{At: 3 * time.Millisecond, Payload: []byte("ij")})
	if err != nil {
		t.Fatal(err)
	}
	deliveries = append(deliveries, output...)
	output, err = relay.CloseWrite(4 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	deliveries = append(deliveries, output...)
	deliveries = append(deliveries, relay.Flush()...)
	acknowledgeByteDeliveries(t, relay, deliveries[1:])

	var payload []byte
	for _, delivery := range deliveries {
		payload = append(payload, delivery.Payload...)
	}
	if !bytes.Equal(payload, []byte("abcdefghij")) {
		t.Fatalf("relayed payload = %q", payload)
	}
	if len(deliveries) != 3 || !deliveries[len(deliveries)-1].HalfClose {
		t.Fatalf("deliveries = %+v", deliveries)
	}
	if err := relay.Verify(); err != nil {
		t.Fatalf("verify: %v; report=%+v", err, relay.Report())
	}
	if relay.Report().Actual != expected {
		t.Fatalf("actual counters = %+v, want %+v", relay.Report().Actual, expected)
	}
}

func TestByteVerifyRequiresFlushedAndAcknowledgedDeliveries(t *testing.T) {
	expected := Counters{
		InputUnits: 1, InputBytes: 2, OutputUnits: 1, OutputBytes: 2,
		FragmentUnits: 2, CoalescedUnits: 1,
	}
	relay, err := NewByteRelay(ByteProfile{
		Phase: "drain", Direction: ClientToServer, Seed: 1,
		FragmentPattern: []int{1}, CoalesceBytes: 4, Expected: &expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	if output, err := relay.Write(ByteChunk{Payload: []byte("ok")}); err != nil || len(output) != 0 {
		t.Fatalf("Write = %+v, %v", output, err)
	}
	if err := relay.Verify(); !errors.Is(err, ErrRelayNotDrained) {
		t.Fatalf("Verify with coalesced buffer = %v", err)
	}
	output := relay.Flush()
	if len(output) != 1 {
		t.Fatalf("Flush = %+v", output)
	}
	if err := relay.Verify(); !errors.Is(err, ErrRelayNotDrained) {
		t.Fatalf("Verify before write acknowledgement = %v", err)
	}
	if err := relay.Acknowledge(2); err != nil {
		t.Fatal(err)
	}
	if err := relay.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestByteRateErrorsRemainCancelableAndConserved(t *testing.T) {
	tests := []struct {
		name     string
		fragment []int
	}{
		{name: "write exceeds token burst"},
		{name: "fragment exceeds token burst", fragment: []int{8}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relay, err := NewByteRelay(ByteProfile{
				Phase: "rate-error", Direction: ClientToServer, Seed: 1,
				Rate:            RateLimit{BytesPerSecond: 4, BurstBytes: 4},
				FragmentPattern: test.fragment, Expected: &Counters{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := relay.Write(ByteChunk{Payload: []byte("oversized")}); err == nil {
				t.Fatal("Write succeeded, want post-input rate error")
			}

			relay.discardPending()
			actual := relay.Report().Actual
			if actual.InputUnits != 1 || actual.InputBytes != 9 ||
				actual.CanceledUnits != 1 || actual.CanceledBytes != 9 {
				t.Fatalf("terminal counters = %+v", actual)
			}
			if err := actual.CheckByteConservation(); err != nil {
				t.Fatal(err)
			}
			if err := relay.verifyDrained(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFragmentAndCoalesceCountersTrackActualBoundaries(t *testing.T) {
	expected := Counters{
		InputUnits: 1, InputBytes: 4,
		OutputUnits: 2, OutputBytes: 4,
		FragmentUnits: 2, CoalescedUnits: 1,
	}
	relay, err := NewByteRelay(ByteProfile{
		Phase: "piece-boundaries", Direction: ClientToServer, Seed: 42,
		FragmentPattern: []int{3}, CoalesceBytes: 2, Expected: &expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err := relay.Write(ByteChunk{Payload: []byte("abcd")})
	if err != nil {
		t.Fatal(err)
	}
	output = append(output, relay.Flush()...)
	var payload []byte
	for _, delivery := range output {
		payload = append(payload, delivery.Payload...)
	}
	if !bytes.Equal(payload, []byte("abcd")) {
		t.Fatalf("payload = %q", payload)
	}
	acknowledgeByteDeliveries(t, relay, output)
	if err := relay.Verify(); err != nil {
		t.Fatalf("verify: %v; report=%+v", err, relay.Report())
	}
}

func TestFragmentPatternMustActuallySplitAWrite(t *testing.T) {
	expected := Counters{
		InputUnits: 1, InputBytes: 3,
		OutputUnits: 1, OutputBytes: 3, FragmentUnits: 1,
	}
	relay, err := NewByteRelay(ByteProfile{
		Phase: "fragment-miss", Direction: ClientToServer, Seed: 42,
		FragmentPattern: []int{8}, Expected: &expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err := relay.Write(ByteChunk{Payload: []byte("abc")})
	if err != nil {
		t.Fatal(err)
	}
	acknowledgeByteDeliveries(t, relay, output)
	if err := relay.Verify(); !errors.Is(err, ErrFaultNotExercised) {
		t.Fatalf("verify error = %v, want ErrFaultNotExercised", err)
	}
}

func TestHalfCloseCannotBeDeliveredBeforeCloseWrite(t *testing.T) {
	expected := Counters{
		InputUnits: 1, InputBytes: 2,
		OutputUnits: 1, OutputBytes: 2,
		FragmentUnits: 2, CoalescedUnits: 1, HalfCloses: 1,
	}
	relay, err := NewByteRelay(ByteProfile{
		Phase: "half-close-causality", Direction: ClientToServer, Seed: 42,
		FragmentPattern: []int{1}, CoalesceBytes: 8,
		RequireHalfClose: true, Expected: &expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	if output, err := relay.Write(ByteChunk{At: time.Millisecond, Payload: []byte("xy")}); err != nil || len(output) != 0 {
		t.Fatalf("buffered write = %+v, %v", output, err)
	}
	const closeAt = 10 * time.Millisecond
	output, err := relay.CloseWrite(closeAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) != 1 || !output[0].HalfClose || output[0].ReadyAt < closeAt {
		t.Fatalf("half-close output = %+v", output)
	}
	acknowledgeByteDeliveries(t, relay, output)
	if err := relay.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func acknowledgeByteDeliveries(t testing.TB, relay *ByteRelay, deliveries []ByteDelivery) {
	t.Helper()
	for _, delivery := range deliveries {
		if err := relay.Acknowledge(uint64(len(delivery.Payload))); err != nil {
			t.Fatalf("acknowledge byte delivery: %v", err)
		}
	}
}
