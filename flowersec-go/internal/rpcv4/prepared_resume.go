package rpcv4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"

// BeginResumePreparation uses the original request identity, route, deadline
// and digest engine. Its caller must already hold the exact accepted target's
// exclusive application-message qualification before invoking this function.
// FinalizePayload receives the canonical ResumeRequest captured from that
// target; neither this handle nor a persisted query reference can rebind it.
func BeginResumePreparation(route ContractRoute, payloadLimit uint32, options UnaryPreparation, reservation, routeReservation resourcev4.Reference) (*PreparedRequest, error) {
	if payloadLimit > 9345 {
		return nil, ErrCapacity
	}
	return beginRequestPreparation(route, payloadLimit, options, 3, reservation, routeReservation)
}
