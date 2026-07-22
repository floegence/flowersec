package weaknet

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestUDPVerifyRequiresAcknowledgedAndFlushedDeliveries(t *testing.T) {
	expected := Counters{InputUnits: 1, InputBytes: 1, OutputUnits: 1, OutputBytes: 1}
	relay, err := NewUDPRelay(UDPProfile{
		Phase: "drain", Direction: ClientToServer, Seed: 1, Expected: &expected,
	}, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := relay.Process(context.Background(), Datagram{Payload: []byte{1}})
	if err != nil || len(output) != 1 {
		t.Fatalf("Process = %+v, %v", output, err)
	}
	if err := relay.Verify(); !errors.Is(err, ErrRelayNotDrained) {
		t.Fatalf("Verify before write acknowledgement = %v", err)
	}
	if err := relay.Acknowledge(1); err != nil {
		t.Fatal(err)
	}
	if err := relay.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestUDPPostInputErrorsCancelAcceptedDatagram(t *testing.T) {
	tests := []struct {
		name    string
		profile UDPProfile
		options UDPOptions
	}{
		{
			name: "NAT rebind callback",
			profile: UDPProfile{
				Phase: "nat-error", Direction: ClientToServer, Seed: 1,
				NATRebindOrdinals: []uint64{1}, Expected: &Counters{},
			},
			options: UDPOptions{NATRebind: func(context.Context, RebindEvent) error {
				return errors.New("rebind failed")
			}},
		},
		{
			name: "datagram exceeds token burst",
			profile: UDPProfile{
				Phase: "rate-error", Direction: ClientToServer, Seed: 1,
				Rate: RateLimit{BytesPerSecond: 4, BurstBytes: 4}, Expected: &Counters{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relay, err := NewUDPRelay(test.profile, test.options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := relay.Process(context.Background(), Datagram{Payload: []byte("oversized")}); err == nil {
				t.Fatal("Process succeeded, want post-input error")
			}

			actual := relay.Report().Actual
			if actual.InputUnits != 1 || actual.InputBytes != 9 ||
				actual.CanceledUnits != 1 || actual.CanceledBytes != 9 {
				t.Fatalf("terminal counters = %+v", actual)
			}
			if err := actual.CheckUDPConservation(); err != nil {
				t.Fatal(err)
			}
			if err := relay.verifyDrained(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUDPRelayDeterministicallyAppliesPacketFaithfulFaults(t *testing.T) {
	expected := Counters{
		InputUnits:       12,
		InputBytes:       53,
		OutputUnits:      8,
		OutputBytes:      32,
		DroppedUnits:     5,
		DroppedBytes:     25,
		OrdinalLossUnits: 1,
		BurstLossUnits:   2,
		OutageUnits:      1,
		MTUDropUnits:     1,
		DelayUnits:       8,
		JitterUnits:      3,
		ReorderedUnits:   1,
		DuplicateUnits:   1,
		DuplicateBytes:   4,
		RateLimitedUnits: 7,
		NATRebinds:       1,
	}
	profile := UDPProfile{
		Phase:             "mixed",
		Direction:         ClientToServer,
		Seed:              0x5eed,
		LossOrdinals:      []uint64{2},
		LossBursts:        []OrdinalRange{{First: 3, Last: 4}},
		Delay:             2 * time.Millisecond,
		JitterScript:      []time.Duration{0, time.Millisecond},
		ReorderOrdinals:   []uint64{6},
		DuplicateOrdinals: []uint64{5},
		Rate:              RateLimit{BytesPerSecond: 4, BurstBytes: 4},
		Outages:           []OrdinalRange{{First: 9, Last: 9}},
		MTU:               4,
		NATRebindOrdinals: []uint64{10},
		Expected:          &expected,
	}

	var rebound []RebindEvent
	options := UDPOptions{NATRebind: func(_ context.Context, event RebindEvent) error {
		rebound = append(rebound, event)
		return nil
	}}
	first := runUDPProfile(t, profile, options)
	second := runUDPProfile(t, profile, UDPOptions{NATRebind: func(context.Context, RebindEvent) error {
		return nil
	}})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same seed/profile produced different deliveries:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if len(rebound) != 1 || rebound[0].Ordinal != 10 || rebound[0].Direction != ClientToServer {
		t.Fatalf("rebind events = %+v", rebound)
	}

	ordinals := make([]uint64, 0, len(first))
	for _, delivery := range first {
		ordinals = append(ordinals, delivery.Ordinal)
	}
	wantOrder := []uint64{1, 5, 5, 7, 6, 10, 11, 12}
	if !reflect.DeepEqual(ordinals, wantOrder) {
		t.Fatalf("delivery order = %v, want %v", ordinals, wantOrder)
	}
}

func runUDPProfile(t *testing.T, profile UDPProfile, options UDPOptions) []UDPDelivery {
	t.Helper()
	relay, err := NewUDPRelay(profile, options)
	if err != nil {
		t.Fatal(err)
	}
	var deliveries []UDPDelivery
	for ordinal := 1; ordinal <= 12; ordinal++ {
		payload := []byte("data")
		if ordinal == 8 {
			payload = []byte("oversized")
		}
		output, err := relay.Process(context.Background(), Datagram{
			At:      time.Duration(ordinal) * time.Millisecond,
			Payload: payload,
		})
		if err != nil {
			t.Fatalf("process ordinal %d: %v", ordinal, err)
		}
		deliveries = append(deliveries, output...)
	}
	deliveries = append(deliveries, relay.Flush()...)
	acknowledgeUDPDeliveries(t, relay, deliveries)
	if err := relay.Verify(); err != nil {
		t.Fatalf("verify: %v; report=%+v", err, relay.Report())
	}
	if got := relay.Report(); got.Actual != *profile.Expected || got.Phase != profile.Phase || got.Direction != profile.Direction {
		t.Fatalf("report = %+v", got)
	}
	return deliveries
}

func acknowledgeUDPDeliveries(t testing.TB, relay *UDPRelay, deliveries []UDPDelivery) {
	t.Helper()
	for _, delivery := range deliveries {
		if err := relay.Acknowledge(len(delivery.Payload)); err != nil {
			t.Fatalf("acknowledge UDP delivery: %v", err)
		}
	}
}
