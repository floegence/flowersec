package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"

// Native service ownership has two real tails: the external worker(s) and the
// original transport. Each keeps the same backing through its physical exit.
// The compound supervisor owns the second pair, including if the external
// worker returns while accepted output is still awaiting authenticated Finish.
func prepareConnExternal(reservation, dependencies resourcev4.Reference, charge resourcev4.Vector) (owned, shared resourcev4.Reference, external *connExternalCleanup, err error) {
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return
	}
	shared, err = dependencies.Borrow()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			owned.Release()
			shared.Release()
			if external != nil {
				external.backing.Release()
				external.dependencies.Release()
			}
		}
	}()
	owned, err = reservation.Take(charge)
	if err != nil {
		return
	}
	external = &connExternalCleanup{done: make(chan struct{})}
	external.backing, err = owned.Borrow()
	if err != nil {
		return
	}
	external.dependencies, err = dependencies.Borrow()
	return
}
