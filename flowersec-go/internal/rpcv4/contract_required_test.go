package rpcv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestRequiredUnaryUsesRegisteredExactContractAndLiveOffer(t *testing.T) {
	for _, execution := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "execution"}[execution], func(t *testing.T) {
			f := newOfferFixture(t, execution, timev4.Interval{LowerMS: 25, UpperMS: 25})
			required := [][32]byte{f.digest}
			if execution {
				if err := f.registry.CheckRequiredUnary(required); !errors.Is(err, ErrMethod) {
					t.Fatal("execution missing offer qualified", err)
				}
				if err := f.registry.RegisterOffer(f.digest, offerBytes(t, f.digest, 0, 100)); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.registry.CheckRequiredUnary(required); err != nil {
				t.Fatal(err)
			}
			if execution {
				f.ticks.Store(101)
				if err := f.registry.CheckRequiredUnary(required); !errors.Is(err, ErrMethod) {
					t.Fatal("expired offer qualified", err)
				}
				if _, err := f.registry.RetireOffers(); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.registry.SetRegistered(f.digest, false); err != nil {
				t.Fatal(err)
			}
			if err := f.registry.CheckRequiredUnary(required); !errors.Is(err, ErrMethod) {
				t.Fatal("unregistered method qualified", err)
			}
			if err := f.registry.WithRequiredUnaryAt(required, timev4.Sample{}, func() error { t.Fatal("invalid time entered publication"); return nil }); !errors.Is(err, ErrConfiguration) {
				t.Fatal(err)
			}
		})
	}
}
