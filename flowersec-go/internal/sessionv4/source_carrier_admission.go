package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"

// SourceCarrierCharge includes the original candidate position's reusable
// metadata. Provider preparation has its own qualified backing; this charge
// covers only the PreparedCarrier owner used across numeric attempts.
func SourceCarrierCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	minimum, err := PreparedCarrierCharge(runtimeBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.ProtectedCharge(minimum)
}

func (refs *sourceReferences) reserveCarriers(c SourceConnectConfig) error {
	refs.carrierOrigin = c.CarrierReservation
	refs.carrierRuntimeBytes = c.CarrierRuntimeBytes
	refs.carrierCount = sourceCarrierReferenceCount(c)
	if refs.carrierCount == 0 {
		if c.Carrier != nil {
			return resourcev4.ErrConfiguration
		}
		return nil
	}
	charge, err := SourceCarrierCharge(c.CarrierRuntimeBytes)
	if err != nil {
		return err
	}
	if err = c.CarrierReservation.CheckSameEnvironment(c.Environment); err != nil {
		return err
	}
	if err = c.CarrierReservation.CheckRoot(c.Root); err != nil {
		return err
	}
	if err = c.CarrierReservation.CheckMinimum(charge); err != nil {
		return err
	}
	minimum, err := PreparedCarrierCharge(c.CarrierRuntimeBytes)
	if err != nil {
		return err
	}
	for i := range refs.carrierCount {
		refs.carriers[i], err = c.Environment.Borrow()
		if err != nil {
			return err
		}
		if i == 0 {
			// Preserve the caller's primary until the Environment accepts all
			// inputs. The original source worker adopts it before Acquire.
			continue
		}
		ref, err := c.Root.Reserve(admissionResourceKey(c.Owner, 400+uint32(i)), charge, c.Scope.Tenant, c.Scope.Session)
		if err != nil {
			return err
		}
		refs.carrierFloors[i], err = resourcev4.NewProtectedReservation(ref, minimum)
		ref.Release()
		if err != nil {
			return err
		}
	}
	if factory, ok := c.Carrier.(AdmittingConsumerCarrierFactory); ok {
		request := CarrierPreparationAdmissionRequest{Clock: c.Admission.Core.Clock, Environment: c.Environment, Reservation: c.CarrierReservation, Scope: c.Scope}
		if err = factory.AdmitPreparations(request, refs.providerPreparations[:refs.carrierCount]); err != nil {
			return err
		}
		for i := range refs.carrierCount {
			if refs.providerPreparations[i] == nil || !refs.providerPreparations[i].Matches(c.Carrier) {
				return resourcev4.ErrOwner
			}
		}
	}
	return nil
}

func (refs *sourceReferences) adoptCarriers(c SourceConnectConfig) error {
	if refs.carrierCount != sourceCarrierReferenceCount(c) || refs.carrierCount == 0 ||
		refs.carrierOrigin != c.CarrierReservation || refs.carrierRuntimeBytes != c.CarrierRuntimeBytes || refs.carrierFloors[0] != nil {
		return resourcev4.ErrOwner
	}
	for _, preparation := range refs.providerPreparations {
		if preparation != nil {
			if err := preparation.Check(); err != nil {
				return err
			}
		}
	}
	minimum, err := PreparedCarrierCharge(c.CarrierRuntimeBytes)
	if err != nil {
		return err
	}
	refs.carrierFloors[0], err = resourcev4.NewProtectedReservation(c.CarrierReservation, minimum)
	return err
}
