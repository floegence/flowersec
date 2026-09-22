package sessionv4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// This fixture exercises the actual pre-READY constructor order with service
// reservations taken before Authenticate. It does not model the complete
// Engine/OpenAdmission/provider admission vector.
type serviceInitializationFixture struct {
	refs       [8]resourcev4.Reference
	resources  *nativeAssemblyFixture
	native     bool
	admission  *OpenAdmission
	runtime    *SessionRuntime
	retire     []func() error
	wait       []func(context.Context) error
	probeSlots [2]ProbeSlot
	pongSlots  [2]PongSlot
	rekeySlots [2]RekeyWaitSlot
}

func reserveServiceInitialization(t *testing.T, native bool) *serviceInitializationFixture {
	t.Helper()
	f := &serviceInitializationFixture{native: native, resources: backgroundResources(t, &openEndpoint{})}
	var charges [8]resourcev4.Vector
	var err error
	charges[0], err = LivenessCharge(2, true)
	if err != nil {
		t.Fatal(err)
	}
	charges[1], err = MaintenanceMessagesCharge(2)
	if err != nil {
		t.Fatal(err)
	}
	charges[2], err = StreamTerminationServiceCharge(0)
	if err != nil {
		t.Fatal(err)
	}
	charges[3] = RekeyServiceCharge(4096, 4)
	charges[4], err = RetirementServiceCharge()
	if err != nil {
		t.Fatal(err)
	}
	decode := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
	if native {
		charges[5], err = MaintenanceIngressCharge(4096)
		if err != nil {
			t.Fatal(err)
		}
		charges[6], err = RecordReceiverCharge(4096, 128, decode)
	} else {
		charges[5], err = SharedIngressCharge(4096, 128, decode)
	}
	if err != nil {
		t.Fatal(err)
	}
	charges[7] = SessionRuntimeCharge()
	for i, charge := range charges {
		if charge != (resourcev4.Vector{}) {
			f.refs[i] = f.resources.reserve(t, charge)
		}
	}
	t.Cleanup(func() {
		if f.runtime != nil {
			f.runtime.Close()
		} else if f.admission != nil {
			f.admission.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if f.runtime != nil {
			if err := f.runtime.WaitCleanup(ctx); err != nil {
				t.Error(err)
				return
			}
		}
		for _, wait := range f.wait {
			if err := wait(ctx); err != nil {
				t.Error(err)
				return
			}
		}
		for _, retire := range f.retire {
			if err := retire(); err != nil {
				t.Error(err)
			}
		}
		if f.runtime != nil {
			if err := f.runtime.Retire(); err != nil {
				t.Error(err)
			}
		}
		for _, ref := range f.refs {
			ref.Release()
		}
		if got := f.resources.root.Snapshot().Reservations; got != 0 {
			t.Error("service reservations leaked", got)
		}
	})
	return f
}

func (f *serviceInitializationFixture) install(engine *cryptov4.Engine, input RuntimeInput, output io.Writer) (err error) {
	_, _, role := engine.ScopeLimits()
	f.admission, err = NewOpenAdmission(engine, role, OpenLimits{Terminal: 5, RejectionReserve: 1, IngressItems: 2, IngressBytes: 65536})
	if err != nil {
		return err
	}
	a := f.admission
	w, err := NewRecordWriter(engine, 0, output)
	if err != nil {
		return err
	}
	p, err := NewLivenessWithPolicy(a, w, f.probeSlots[:], AutomaticLivenessPolicy{1000000, 1000, 1000, 3}, f.refs[0])
	if err != nil {
		return err
	}
	f.retire, f.wait = append(f.retire, p.retire), append(f.wait, p.WaitCleanup)
	q, err := NewMaintenanceMessages(p, f.pongSlots[:], MaintenanceMessagePolicy{8, 1000, 10000}, f.refs[1])
	if err != nil {
		return err
	}
	f.retire, f.wait = append(f.retire, q.retire), append(f.wait, q.WaitCleanup)
	termination, err := NewStreamTerminationService(a, w, StreamTerminationPolicy{10000, 1000, 8}, f.refs[2])
	if err != nil {
		return err
	}
	f.retire, f.wait = append(f.retire, termination.retire), append(f.wait, termination.WaitCleanup)
	original := engine.SessionParameters()
	if _, err := NewRekeyCredit(a, original.Contract.Limits().Rekey, original.IssuedAtMS, original.SessionNotAfterMS, engine.Clock()); err != nil {
		return err
	}
	if _, err := NewRekeyCauses(a, f.rekeySlots[:]); err != nil {
		return err
	}
	if _, err := NewBarriers(a); err != nil {
		return err
	}
	rekey, err := NewRekeyService(a, w, RekeyPhaseBudgets{5000, 10000, 30000}, f.refs[3])
	if err != nil {
		return err
	}
	f.retire, f.wait = append(f.retire, rekey.retire), append(f.wait, rekey.WaitCleanup)
	retirement, err := NewRetirement(a, w)
	if err != nil {
		return err
	}
	retiring, err := NewRetirementService(retirement, 10000, f.refs[4])
	if err != nil {
		return err
	}
	f.retire, f.wait = append(f.retire, retiring.retire), append(f.wait, retiring.WaitCleanup)
	config := SessionRuntimeConfig{Admission: a, Input: input, DispatchTimeoutMS: 10000, Reservation: f.refs[7]}
	decode := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
	if f.native {
		config.MaintenanceIngress, err = NewMaintenanceIngress(a, &CarrierAssociation{}, MaintenanceIngressPolicy{10000, 1000, 8}, 128, decode, f.refs[5], f.refs[6])
		if err != nil {
			return err
		}
		f.retire, f.wait = append(f.retire, config.MaintenanceIngress.retire), append(f.wait, config.MaintenanceIngress.WaitCleanup)
	} else {
		config.SharedIngress, err = NewSharedIngress(a, &CarrierAssociation{}, SharedDiscardPolicy{16, 65536, 10000}, 128, decode, f.refs[5])
		if err != nil {
			return err
		}
		f.retire, f.wait = append(f.retire, config.SharedIngress.Retire), append(f.wait, config.SharedIngress.WaitCleanup)
	}
	f.runtime, err = NewSessionRuntime(config)
	if err != nil {
		return err
	}
	if _, err := engine.ScopeFrontier(0, role); !errors.Is(err, cryptov4.ErrNotReady) {
		return fmt.Errorf("private construction exposed frontier: %w", err)
	}
	return nil
}

func TestOriginalHandshakeInstallsServicesBeforeReady(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprint("native=", native), func(t *testing.T) {
			pair, configs := initialTestPair(t, protocolv4.DHProfileX25519, "stream")
			fixtures := [2]*serviceInitializationFixture{reserveServiceInitialization(t, native), reserveServiceInitialization(t, native)}
			var results [2]chan error
			for role := range 2 {
				results[role] = make(chan error, 1)
				go func() {
					records := initialRecordLimits()
					records.MaxScopes = 0
					s := pair[role].stream
					engine, err := pair[role].Authenticate(configs[role], records, func(e *cryptov4.Engine) error {
						return fixtures[role].install(e, &runtimeTestInput{Reader: s, interrupt: func() { _ = s.Close() }}, s)
					})
					if err == nil && engine != fixtures[role].admission.engine {
						err = errors.New("READY replaced original engine")
					}
					results[role] <- err
				}()
			}
			for role := range 2 {
				if err := waitRuntime(t, results[role]); err != nil {
					t.Fatal(role, err)
				}
				a := fixtures[role].admission
				if _, err := a.engine.ScopeFrontier(0, a.direction); err != nil {
					t.Fatal("dual READY did not activate original services", err)
				}
				if a.runtime != fixtures[role].runtime || a.rekeyService == nil || a.retirementService == nil || a.termination == nil || a.maintenanceMessages == nil {
					t.Fatal("runtime missed required maintenance service")
				}
			}
		})
	}
}
