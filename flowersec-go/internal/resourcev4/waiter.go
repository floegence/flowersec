package resourcev4

import (
	"context"
	"errors"
	"unsafe"
)

const MaxWaiterRequests = 4

// ReservationWaiter is one preadmitted SDK coordinator's bounded budget wait.
// It is not an application job or an admission queue outside the root. One
// waiter retains at most four original requests and no payload or goroutine.
// Closing it cancels only its waiting/acquired local vector, never other work.
type ReservationWaiter struct {
	root                    *Root
	reservation             Reference
	resultScope             Reference
	previous, next          *ReservationWaiter
	requests                [MaxWaiterRequests]Request
	accounts                [MaxWaiterRequests][MaxAccountsPerCharge]Account
	output                  [MaxWaiterRequests]Reference
	wake                    chan struct{}
	count                   int
	waiting, active, closed bool
	failure                 error
}

func ReservationWaiterCharge(runtimeBytes uint64) (Vector, error) {
	if runtimeBytes == 0 {
		return Vector{}, ErrConfiguration
	}
	return (Vector{SDKBytes: uint64(unsafe.Sizeof(ReservationWaiter{})), Items: 1, WorkSlots: 1}).Add(Vector{SDKBytes: runtimeBytes})
}

func NewReservationWaiter(root *Root, reservation Reference, runtimeBytes uint64) (*ReservationWaiter, error) {
	charge, err := ReservationWaiterCharge(runtimeBytes)
	if err != nil || root == nil || reservation.root != root {
		return nil, ErrConfiguration
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	return &ReservationWaiter{root: root, reservation: owned, wake: make(chan struct{}, 1)}, nil
}

// Reserve has exactly one active caller. Requests are captured by value before
// waiting; all account references remain in their original generations. The
// original caller supplies its fixed assembly/cancellation deadline context.
// A canceled waiter returns zero ownership, including a just-granted vector.
func (w *ReservationWaiter) Reserve(ctx context.Context, requests []Request, output []Reference) error {
	return w.reserve(ctx, Reference{}, requests, output)
}

// ReserveResultScope keeps the same fixed waiter for the current completed
// input. Only Session/direction scopes may differ from its original admission;
// the result must still own every original Environment/tenant/pool account.
func (w *ReservationWaiter) ReserveResultScope(ctx context.Context, result Reference, requests []Request, output []Reference) error {
	if result == (Reference{}) {
		return ErrOwner
	}
	return w.reserve(ctx, result, requests, output)
}

func (w *ReservationWaiter) reserve(ctx context.Context, result Reference, requests []Request, output []Reference) error {
	if w == nil || ctx == nil || len(requests) == 0 || len(requests) > MaxWaiterRequests || len(requests) != len(output) {
		return ErrConfiguration
	}
	for _, ref := range output {
		if ref != (Reference{}) {
			return ErrOwner
		}
	}
	r := w.root
	r.mu.Lock()
	if w.closed || w.active {
		r.mu.Unlock()
		return ErrClosed
	}
	s, c := w.reservation.slotsLocked()
	if s == nil {
		r.mu.Unlock()
		return ErrOwner
	}
	scope, scopeCharge := s, c
	if result != (Reference{}) {
		if result.root != r {
			r.mu.Unlock()
			return ErrOwner
		}
		scope, scopeCharge = result.slotsLocked()
		if scope == nil || !scope.primary || !scopeCharge.resultOwner || scope.owner.Environment != s.owner.Environment {
			r.mu.Unlock()
			return ErrOwner
		}
		for _, account := range scope.accounts[:scope.count] {
			if accountIndex(s.accounts[:s.count], account) < 0 {
				r.mu.Unlock()
				return ErrOwner
			}
		}
		for _, account := range s.accounts[:s.count] {
			kind := account.slotLocked(r).key.Kind
			if kind != SessionAccount && kind != DirectionAccount && accountIndex(scope.accounts[:scope.count], account) < 0 {
				r.mu.Unlock()
				return ErrOwner
			}
		}
	}
	if err := r.checkCharge(scope, scopeCharge); err != nil {
		r.mu.Unlock()
		return err
	}
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return err
	}
	for i, request := range requests {
		if len(request.Accounts) != scope.count || request.Owner.Environment != s.owner.Environment || request.Owner.ProfileRevision != s.owner.ProfileRevision {
			w.clearLocked()
			r.mu.Unlock()
			return ErrOwner
		}
		for index, account := range request.Accounts {
			if accountIndex(scope.accounts[:scope.count], account) < 0 || accountIndex(request.Accounts[:index], account) >= 0 {
				w.clearLocked()
				r.mu.Unlock()
				return ErrOwner
			}
		}
		w.requests[i] = request
		copy(w.accounts[i][:], request.Accounts)
		w.requests[i].Accounts = w.accounts[i][:len(request.Accounts)]
	}
	w.count, w.active, w.waiting = len(requests), true, true
	w.resultScope = result
	w.previous = r.waitLast
	if r.waitLast != nil {
		r.waitLast.next = w
	} else {
		r.waitFirst = w
	}
	r.waitLast = w
	r.drainWaitersLocked()
	r.mu.Unlock()
	for {
		r.mu.Lock()
		err := ctx.Err()
		if w.closed && err == nil {
			err = ErrClosed
		}
		if err != nil || !w.waiting {
			if w.waiting {
				r.unlinkWaiterLocked(w)
			}
			if err == nil {
				err = w.failure
			}
			if err == nil {
				copy(output, w.output[:w.count])
			} else {
				for _, ref := range w.output[:w.count] {
					if ref.root != nil {
						ref.releaseLocked()
					}
				}
			}
			w.clearLocked()
			w.active = false
			w.cleanupLocked()
			r.drainWaitersLocked()
			r.mu.Unlock()
			return err
		}
		r.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-w.wake:
		}
	}
}

func (r *Root) unlinkWaiterLocked(w *ReservationWaiter) {
	if w.previous != nil {
		w.previous.next = w.next
	} else {
		r.waitFirst = w.next
	}
	if w.next != nil {
		w.next.previous = w.previous
	} else {
		r.waitLast = w.previous
	}
	w.previous, w.next, w.waiting = nil, nil, false
}

// The head gets its complete vector before later ordinary admissions. Resource
// operations use the same nonallocating reserve/rollback code; no callback or
// provider runs here. A full head remains finite and waits for an actual refund.
func (r *Root) drainWaitersLocked() {
	if r.drainingWaiters {
		return
	}
	r.drainingWaiters = true
	defer func() { r.drainingWaiters = false }()
	for w := r.waitFirst; w != nil; w = r.waitFirst {
		var err error
		s, c := w.reservation.slotsLocked()
		if s == nil {
			err = ErrOwner
		} else {
			if w.resultScope != (Reference{}) {
				s, c = w.resultScope.slotsLocked()
			}
			if s == nil {
				err = ErrOwner
			} else {
				err = r.checkCharge(s, c)
			}
		}
		if err == nil {
			for i, request := range w.requests[:w.count] {
				var ref Reference
				if request.ResultOwner {
					ref, err = r.reserveResultLocked(request.Owner, request.Charge, request.Accounts)
				} else {
					ref, err = r.reserveLocked(request.Owner, request.Charge, request.Accounts)
				}
				if err != nil {
					break
				}
				w.output[i] = ref
			}
		}
		if err != nil {
			for _, ref := range w.output[:w.count] {
				if ref.root != nil {
					ref.releaseLocked()
				}
			}
			clear(w.output[:])
			if errors.Is(err, ErrCapacity) {
				return
			}
		}
		w.failure = err
		r.unlinkWaiterLocked(w)
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
}

func (w *ReservationWaiter) Close() {
	if w == nil {
		return
	}
	r := w.root
	r.mu.Lock()
	defer r.mu.Unlock()
	w.closed = true
	if w.waiting {
		r.unlinkWaiterLocked(w)
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
	w.cleanupLocked()
	r.drainWaitersLocked()
}
func (w *ReservationWaiter) clearLocked() {
	w.resultScope = Reference{}
	clear(w.requests[:])
	clear(w.accounts[:])
	clear(w.output[:])
	w.count, w.failure = 0, nil
}

// DetachSessionScope is used only after the original Stream's actual I/O
// retirement. An active result wait carries its independently checked scope.
func (w *ReservationWaiter) DetachSessionScope() error {
	if w == nil {
		return ErrOwner
	}
	return w.reservation.DetachSessionScope()
}
func (w *ReservationWaiter) cleanupLocked() {
	if w.closed && !w.active && w.reservation.root != nil {
		w.reservation.releaseLocked()
		w.reservation = Reference{}
	}
}
