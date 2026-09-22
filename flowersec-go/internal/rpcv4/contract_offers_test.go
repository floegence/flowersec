package rpcv4

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type offerFixture struct {
	rpc      *rpcFixture
	registry *ContractRoutes
	clock    *timev4.Clock
	ticks    atomic.Uint64
	digest   [32]byte
}

func newOfferFixture(t *testing.T, execution bool, start timev4.Interval) *offerFixture {
	t.Helper()
	h, contract, _ := inputFixture(t, execution, nil)
	defer contract.Release()
	f := &offerFixture{digest: h.Fields().ServiceContractDigest}
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 10000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: f.ticks.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, start); err != nil {
		t.Fatal(err)
	}
	f.clock = clock
	var buffer [8192]byte
	count, err := contract.CopyCanonical(buffer[:])
	if err != nil {
		t.Fatal(err)
	}
	rpc := newRPCFixture(t, contract, 1)
	f.rpc = rpc
	config := ContractRoutesConfig{Methods: []MethodRoutes{{Contracts: [][]byte{buffer[:count]}, OfferWindowMS: 1000}}, ContractNodes: 768, RuntimeBytes: 4096, Clock: clock}
	charge, err := ContractRoutesCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	f.registry, err = NewContractRoutes(config, rpc.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.registry.Close)
	return f
}
func offerBytes(t *testing.T, digest [32]byte, start, end uint64) []byte {
	t.Helper()
	wire, err := protocolv4.EncodeMap(make([]byte, 256), "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}, {Name: "not_before_ms", Number: start}, {Name: "not_after_ms", Number: end}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// v4.go_contract_query.registry_windows
func TestContractOffersPreserveOriginalDistinctWindows(t *testing.T) {
	f := newOfferFixture(t, true, timev4.Interval{LowerMS: 25, UpperMS: 25})
	r := f.registry
	first, second := offerBytes(t, f.digest, 0, 100), offerBytes(t, f.digest, 50, 150)
	if err := r.RegisterOffer(f.digest, first); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterOffer(f.digest, second); err != nil {
		t.Fatal(err)
	}
	if _, err := r.OfferForAdmission(f.digest, 125); !errors.Is(err, ErrMethod) {
		t.Fatal("overlap synthesized an unauthorized outer window", err)
	}
	if got, err := r.OfferForAdmission(f.digest, 100); err != nil || got.NotBeforeMS != 0 || got.NotAfterMS != 100 {
		t.Fatal(got, err)
	}
	if got, err := r.OfferForQuery(f.digest); err != nil || got.NotBeforeMS != 0 || got.NotAfterMS != 100 {
		t.Fatal("query used a future window", got, err)
	}
	generation := r.generation
	if err := r.RegisterOffer(f.digest, first); err != nil || r.generation != generation {
		t.Fatal("duplicate window changed revision", err)
	}
	clear(first)
	clear(second)
	f.ticks.Store(50)
	if got, err := r.OfferForAdmission(f.digest, 125); err != nil || got.NotBeforeMS != 50 || got.NotAfterMS != 150 {
		t.Fatal("original later window unavailable", got, err)
	}
	if got, err := r.OfferForQuery(f.digest); err != nil || got.NotBeforeMS != 50 || got.NotAfterMS != 150 {
		t.Fatal("query failed to select the original available renewal", got, err)
	}
}

func TestContractOffersRetireOnlyDefinitelyExpiredAndNeverEvict(t *testing.T) {
	f := newOfferFixture(t, true, timev4.Interval{LowerMS: 0, UpperMS: 20})
	r := f.registry
	for i := uint64(0); i < 8; i++ {
		if err := r.RegisterOffer(f.digest, offerBytes(t, f.digest, 0, 100+i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.RegisterOffer(f.digest, offerBytes(t, f.digest, 0, 200)); !errors.Is(err, ErrCapacity) {
		t.Fatal("full set evicted commitment", err)
	}
	f.ticks.Store(90)
	if count, err := r.RetireOffers(); err != nil || count != 0 {
		t.Fatal("uncertainty retired active window", count, err)
	}
	f.ticks.Store(100)
	if count, err := r.RetireOffers(); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err := r.RegisterOffer(f.digest, offerBytes(t, f.digest, 0, 200)); err != nil {
		t.Fatal(err)
	}
	f.ticks.Store(108)
	if count, err := r.RetireOffers(); err != nil || count != 7 {
		t.Fatal(count, err)
	}
	if got, err := r.OfferForQuery(f.digest); err != nil || got.NotAfterMS != 200 {
		t.Fatal(got, err)
	}
	if err := r.RegisterOffer(f.digest, offerBytes(t, f.digest, 0, 100)); !errors.Is(err, ErrMethod) {
		t.Fatal("expired window revived", err)
	}
}

func TestContractOffersRejectForeignNonexecutionAndInvalidClock(t *testing.T) {
	for _, execution := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "execution"}[execution], func(t *testing.T) {
			f := newOfferFixture(t, execution, timev4.Interval{LowerMS: 1, UpperMS: 1})
			r := f.registry
			wire := offerBytes(t, f.digest, 0, 100)
			if !execution {
				if err := r.RegisterOffer(f.digest, wire); err == nil {
					t.Fatal("transient gained execution window")
				}
				return
			}
			if err := r.RegisterOffer(f.digest, wire); err != nil {
				t.Fatal(err)
			}
			if err := r.RegisterOffer(f.digest, offerBytes(t, [32]byte{55}, 0, 100)); !errors.Is(err, protocolv4.CBORFailure("offer_contract_mismatch")) {
				t.Fatal(err)
			}
			if err := r.RegisterOffer(f.digest, offerBytes(t, f.digest, 0, 1001)); !errors.Is(err, protocolv4.CBORFailure("offer_window")) {
				t.Fatal(err)
			}
			if _, err := r.OfferForAdmission(f.digest, 1); !errors.Is(err, ErrMethod) {
				t.Fatal("cutoff not after current upper bound", err)
			}
			f.clock.Close()
			if _, err := r.OfferForQuery(f.digest); err == nil {
				t.Fatal("closed clock served a usable window")
			}
			if _, err := r.RetireOffers(); err == nil {
				t.Fatal("closed clock retired commitment")
			}
			if r.entries[0].offerCount != 1 {
				t.Fatal("clock loss erased old window")
			}
		})
	}
}
