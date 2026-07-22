package weaknet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestProfilesRejectInvalidDirectionRangesAndTCPPacketFaults(t *testing.T) {
	validUDP := UDPProfile{
		Phase:     "connect",
		Direction: ClientToServer,
		Seed:      42,
		Expected:  &Counters{},
	}
	if err := validUDP.Validate(); err != nil {
		t.Fatalf("valid UDP profile: %v", err)
	}

	invalidDirection := validUDP
	invalidDirection.Direction = "sideways"
	if err := invalidDirection.Validate(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("direction error = %v, want ErrInvalidProfile", err)
	}

	invalidRange := validUDP
	invalidRange.LossBursts = []OrdinalRange{{First: 4, Last: 3}}
	if err := invalidRange.Validate(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("range error = %v, want ErrInvalidProfile", err)
	}

	for name, mutate := range map[string]func(*ByteProfile){
		"loss":      func(p *ByteProfile) { p.LossOrdinals = []uint64{1} },
		"reorder":   func(p *ByteProfile) { p.ReorderOrdinals = []uint64{1} },
		"duplicate": func(p *ByteProfile) { p.DuplicateOrdinals = []uint64{1} },
		"mtu":       func(p *ByteProfile) { p.MTU = 1200 },
	} {
		t.Run(name, func(t *testing.T) {
			profile := ByteProfile{
				Phase:     "steady",
				Direction: ServerToClient,
				Seed:      42,
				Expected:  &Counters{},
			}
			mutate(&profile)
			if err := profile.Validate(); !errors.Is(err, ErrByteFidelity) {
				t.Fatalf("error = %v, want ErrByteFidelity", err)
			}
		})
	}
}

func TestConfiguredFaultMustBeExercised(t *testing.T) {
	profile := UDPProfile{
		Phase:        "loss-miss",
		Direction:    ClientToServer,
		Seed:         42,
		LossOrdinals: []uint64{9},
		Expected: &Counters{
			InputUnits:  1,
			InputBytes:  1,
			OutputUnits: 1,
			OutputBytes: 1,
		},
	}
	relay, err := NewUDPRelay(profile, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := relay.Process(context.Background(), Datagram{Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	acknowledgeUDPDeliveries(t, relay, output)
	if err := relay.Verify(); !errors.Is(err, ErrFaultNotExercised) {
		t.Fatalf("verify error = %v, want ErrFaultNotExercised", err)
	}
}

func TestConfiguredUDPQueueMustOverflow(t *testing.T) {
	expected := Counters{InputUnits: 1, InputBytes: 1, OutputUnits: 1, OutputBytes: 1}
	relay, err := NewUDPRelay(UDPProfile{
		Phase: "queue-miss", Direction: ClientToServer, Seed: 42,
		QueueUnits: 2, QueueBytes: 2, Expected: &expected,
	}, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := relay.Process(context.Background(), Datagram{Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	acknowledgeUDPDeliveries(t, relay, deliveries)
	if err := relay.Verify(); !errors.Is(err, ErrFaultNotExercised) || !strings.Contains(err.Error(), "queue overflow") {
		t.Fatalf("Verify error = %v, want queue-overflow ErrFaultNotExercised", err)
	}
}

func TestSeededRandomLossIsDeterministicAndMustBeExercised(t *testing.T) {
	run := func(seed int64, basisPoints uint32, count int) (Counters, error) {
		var losses uint64
		for ordinal := 1; ordinal <= count; ordinal++ {
			if seededRandomLoss(seed, uint64(ordinal), basisPoints) {
				losses++
			}
		}
		expected := Counters{
			InputUnits: uint64(count), InputBytes: uint64(count),
			OutputUnits: uint64(count) - losses, OutputBytes: uint64(count) - losses,
			DroppedUnits: losses, DroppedBytes: losses, RandomLossUnits: losses,
		}
		relay, err := NewUDPRelay(UDPProfile{
			Phase: "random-loss", Direction: ClientToServer, Seed: seed,
			RandomLossBasisPoints: basisPoints, Expected: &expected,
		}, UDPOptions{})
		if err != nil {
			return Counters{}, err
		}
		for ordinal := 0; ordinal < count; ordinal++ {
			deliveries, err := relay.Process(context.Background(), Datagram{Payload: []byte{byte(ordinal)}})
			if err != nil {
				return Counters{}, err
			}
			for _, delivery := range deliveries {
				if err := relay.Acknowledge(len(delivery.Payload)); err != nil {
					return Counters{}, err
				}
			}
		}
		return relay.Report().Actual, relay.Verify()
	}

	first, err := run(20260720, 2500, 128)
	if err != nil {
		t.Fatal(err)
	}
	second, err := run(20260720, 2500, 128)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.RandomLossUnits == 0 {
		t.Fatalf("seeded random loss is not repeatable or was not hit: first=%+v second=%+v", first, second)
	}

	_, err = run(20260720, 1, 1)
	if !errors.Is(err, ErrFaultNotExercised) || !strings.Contains(err.Error(), "random loss") {
		t.Fatalf("unhit random loss error = %v, want ErrFaultNotExercised", err)
	}
}

func TestConservationChecksRejectLostAccounting(t *testing.T) {
	udp := Counters{InputUnits: 2, InputBytes: 8, OutputUnits: 1, OutputBytes: 4}
	if err := udp.CheckUDPConservation(); !errors.Is(err, ErrConservation) {
		t.Fatalf("UDP conservation error = %v, want ErrConservation", err)
	}
	stream := Counters{InputBytes: 8, OutputBytes: 7}
	if err := stream.CheckByteConservation(); !errors.Is(err, ErrConservation) {
		t.Fatalf("byte conservation error = %v, want ErrConservation", err)
	}
	udp = Counters{InputUnits: 2, InputBytes: 8, OutputUnits: 1, OutputBytes: 4, CanceledUnits: 1, CanceledBytes: 4}
	if err := udp.CheckUDPConservation(); err != nil {
		t.Fatalf("UDP canceled delivery conservation: %v", err)
	}
	stream = Counters{InputBytes: 8, OutputBytes: 7, CanceledBytes: 1}
	if err := stream.CheckByteConservation(); err != nil {
		t.Fatalf("byte canceled delivery conservation: %v", err)
	}
}

func TestOutageRangeRequiresPositiveDurationForByteRelay(t *testing.T) {
	profile := ByteProfile{
		Phase:     "outage",
		Direction: ClientToServer,
		Seed:      42,
		Outages:   []TimedOutage{{Ordinals: OrdinalRange{First: 1, Last: 2}}},
		Expected:  &Counters{},
	}
	if err := profile.Validate(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("error = %v, want ErrInvalidProfile", err)
	}
	profile.Outages[0].Duration = time.Second
	if err := profile.Validate(); err != nil {
		t.Fatalf("valid timed outage: %v", err)
	}
}

func TestUDPQueueLimitsMustBeBoundedByUnitsAndBytesTogether(t *testing.T) {
	for _, profile := range []UDPProfile{
		{Phase: "queue", Direction: ClientToServer, Seed: 42, QueueUnits: 1, Expected: &Counters{}},
		{Phase: "queue", Direction: ClientToServer, Seed: 42, QueueBytes: 1, Expected: &Counters{}},
	} {
		if err := profile.Validate(); !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("queue validation error = %v, want ErrInvalidProfile", err)
		}
	}
}
