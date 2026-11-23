package resourcev4

// Request describes one distinct allocation in a trusted local admission
// plan. Repeated backing is borrowed or transferred, never inferred from
// equal byte counts. The caller owns the bounded plan and output storage.
type Request struct {
	ResultOwner bool
	Owner       OwnerKey
	Charge      Vector
	Accounts    []Account
}

// ReserveBatch admits all original owners under one root gate. Either every
// account/dimension and metadata slot is charged, or none is. No partial
// reservation escapes on failure and no budget lock crosses allocation,
// provider, store, crypto or application work. Generations consumed by an
// aborted attempt are never rewound. Plans cannot cross budget authorities.
func (r *Root) ReserveBatch(requests []Request, output []Reference) error {
	if r == nil || len(requests) == 0 || len(requests) != len(output) || len(requests) > len(r.charges) {
		return ErrConfiguration
	}
	for _, existing := range output {
		if existing != (Reference{}) {
			return ErrOwner
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drainWaitersLocked()
	for i, request := range requests {
		var ref Reference
		var err error
		if request.ResultOwner {
			ref, err = r.reserveResultLocked(request.Owner, request.Charge, request.Accounts)
		} else {
			ref, err = r.reserveLocked(request.Owner, request.Charge, request.Accounts)
		}
		if err != nil {
			for _, acquired := range output[:i] {
				acquired.releaseLocked()
			}
			clear(output)
			return err
		}
		output[i] = ref
	}
	return nil
}
