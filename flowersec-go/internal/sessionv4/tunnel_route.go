package sessionv4

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// TunnelCarrierPreparation names an already admitted SDK listener or dialer.
// It receives the original fixed selection and its complete carrier charge.
// Any nonnil result transfers its physical cleanup tail, including on error.
// A relay preparation must return an original PreparedRelay owner; an endpoint
// carrier, arbitrary stream or independently constructed connection is refused.
type TunnelCarrierPreparation func(context.Context, PreparedCarrierConfig) (*PreparedCarrier, error)

// TunnelRouteConfig is trusted deployment input, never parsed from a hop request.
// The relay receives only public Grants, identities, route and SessionContract.
// Table must have the original committed issuer publication; a valid signature
// alone cannot create a relay claim or recover an absent original registration.
type TunnelRouteConfig struct {
	Pair         RelayMessagePairConfig
	Hops         [2]RelayHopConfig
	Carriers     [2]PreparedCarrierConfig
	Prepare      [2]TunnelCarrierPreparation
	Store        *ledgerv4.SQLiteStore
	Table        *ledgerv4.SQLiteRelayAuthorityTable
	Root         *resourcev4.Root
	Owner        resourcev4.OwnerKey
	Accounts     []resourcev4.Account
	RuntimeBytes uint64
}

// TunnelRoute admits both physical preparations and all hop/claim positions
// before either provider runs. It drives the actual HOP_AUTH and claim owners,
// then delegates opaque forwarding to the original pair. No Artifact, endpoint
// admission, signing or server-allow capability is held by this relay owner.
type TunnelRoute struct {
	runner                                          TunnelRouteRun
	mu                                              sync.Mutex
	c                                               TunnelRouteConfig
	pair                                            *RelayMessagePair
	hops                                            [2]*RelayHop
	prepared                                        [2]*PreparedCarrier
	maps                                            [2][3]*protocolv4.SignedMap
	codecs                                          [2][3]*protocolv4.SignedMapCodec
	refs                                            [15]resourcev4.Reference
	hopRefs                                         [2]RelayHopReservations
	reservation, shared, store, table, dependencies resourcev4.Reference
	carrierRefs                                     [2]resourcev4.Reference
	cancel                                          context.CancelFunc
	settled                                         chan struct{}
	done                                            chan struct{}
	results                                         chan error
	started, running, closed, cleaning, cleaned     bool
}

func TunnelRouteCharge(c TunnelRouteConfig) (resourcev4.Vector, error) {
	if c.Store == nil || c.Table == nil || c.Root == nil || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || c.RuntimeBytes == 0 || c.Prepare[0] == nil || c.Prepare[1] == nil {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if _, err := RelayMessagePairCharge(c.Pair); err != nil {
		return resourcev4.Vector{}, err
	}
	bytes := uint64(unsafe.Sizeof(TunnelRoute{})) + 2048
	for side := range c.Hops {
		h, p := c.Hops[side], c.Carriers[side]
		if h.Pair != nil || h.Initial.Role != protocolv4.Direction(side) || (h.Initial.Deadline != c.Pair.PreparationDeadline || !h.Initial.Deadline.BelongsTo(c.Pair.Clock)) || p.Role != protocolv4.Direction(side) || p.Deadline != h.Initial.Deadline || p.Reservation != (resourcev4.Reference{}) || p.Environment != (resourcev4.Reference{}) || p.RuntimeBytes == 0 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		for i, m := range []*protocolv4.SignedMap{h.Grant, h.EndpointCertificate, h.RelayCertificate} {
			if m == nil {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
			schema := "IdentityCertificate"
			if i == 0 {
				schema = "Grant"
			}
			limit, err := protocolv4.SchemaByteLimit(schema)
			if err != nil {
				return resourcev4.Vector{}, err
			}
			n, err := protocolv4.SignedMapBackingBytes(schema, limit, h.MapNodes)
			if err != nil {
				return resourcev4.Vector{}, err
			}
			bytes += n
		}
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: 1, resourcev4.WorkSlots: 3, resourcev4.Tasks: 3}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// NewTunnelRoute performs only bounded local admission and public-map capture.
// Constructor failure starts no provider work and releases its own positions.
func NewTunnelRoute(c TunnelRouteConfig, reservation, dependencies resourcev4.Reference) (_ *TunnelRoute, err error) {
	charge, err := TunnelRouteCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	r := &TunnelRoute{c: c, reservation: owned, settled: make(chan struct{}), done: make(chan struct{}), results: make(chan error, 2)}
	success := false
	defer func() {
		if !success {
			r.Close()
			_ = r.WaitCleanup(context.Background())
		}
	}()
	r.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	r.dependencies = dependencies
	var identity ledgerv4.SQLiteIdentity
	var recordBytes uint32
	r.store, identity, recordBytes, err = c.Store.RelayReference(dependencies)
	if err != nil {
		return nil, err
	}
	r.table, err = c.Table.ReferenceFor(identity, dependencies)
	if err != nil {
		return nil, err
	}
	// Own the account slice and each public signed map before provider work.
	r.c.Accounts = append([]resourcev4.Account(nil), c.Accounts...)
	for side := range c.Hops {
		if c.Hops[side].Clock != c.Pair.Clock || c.Hops[side].MaxRecordBytes != recordBytes {
			return nil, resourcev4.ErrOwner
		}
		for i, original := range []*protocolv4.SignedMap{c.Hops[side].Grant, c.Hops[side].EndpointCertificate, c.Hops[side].RelayCertificate} {
			schema := "IdentityCertificate"
			if i == 0 {
				schema = "Grant"
			}
			limit, e := protocolv4.SchemaByteLimit(schema)
			if e != nil {
				return nil, e
			}
			r.codecs[side][i], err = protocolv4.NewImmutableSignedMapCodec(schema, limit, c.Hops[side].MapNodes)
			if err != nil {
				return nil, err
			}
			r.maps[side][i], err = r.codecs[side][i].CopyVerified(original, protocolv4.DecodeContext{})
			if err != nil {
				return nil, err
			}
		}
		r.c.Hops[side].Grant, r.c.Hops[side].EndpointCertificate, r.c.Hops[side].RelayCertificate = r.maps[side][0], r.maps[side][1], r.maps[side][2]
	}
	pairCharge, err := RelayMessagePairCharge(c.Pair)
	if err != nil {
		return nil, err
	}
	r.refs[0], err = r.reserve(pairCharge)
	if err != nil {
		return nil, err
	}
	r.pair, err = NewRelayMessagePair(c.Pair, r.refs[0], dependencies)
	if err != nil {
		return nil, err
	}
	for side := range c.Hops {
		h := &r.c.Hops[side]
		h.Pair = r.pair
		owner, initial, subscriptions, meter, claim, invocation, e := RelayHopCharges(*h)
		if e != nil {
			return nil, e
		}
		carrier, e := PreparedCarrierCharge(c.Carriers[side].RuntimeBytes)
		if e != nil {
			return nil, e
		}
		charges := [7]resourcev4.Vector{carrier, owner, initial, subscriptions, meter, claim, invocation}
		offset := 1 + side*7
		for i, cost := range charges {
			r.refs[offset+i], err = r.reserve(cost)
			if err != nil {
				return nil, err
			}
		}
		r.carrierRefs[side], err = r.refs[offset].Borrow()
		if err != nil {
			return nil, err
		}
		r.c.Carriers[side].Reservation, r.c.Carriers[side].Environment = r.refs[offset], dependencies
		r.c.Carriers[side].relay = true
		r.hopRefs[side] = RelayHopReservations{Owner: r.refs[offset+1], Initial: r.refs[offset+2], Subscriptions: r.refs[offset+3], Meter: r.refs[offset+4], Claim: r.refs[offset+5], Invocation: r.refs[offset+6]}
	}
	success = true
	return r, nil
}

func (r *TunnelRoute) reserve(charge resourcev4.Vector) (resourcev4.Reference, error) {
	owner := r.c.Owner
	if _, err := rand.Read(owner.Instance[:]); err != nil {
		return resourcev4.Reference{}, err
	}
	if _, err := rand.Read(owner.Backing[:]); err != nil {
		return resourcev4.Reference{}, err
	}
	return r.c.Root.Reserve(owner, charge, r.c.Accounts...)
}

func (r *TunnelRoute) CheckEnvironment(environment resourcev4.Reference) error {
	if r == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return resourcev4.ErrClosed
	}
	return r.reservation.CheckSameEnvironment(environment)
}

// TunnelRouteRun is the original once-owned hosted execution. Claiming it
// transfers local dispatch only; it creates no durable claim or forwarding.
type TunnelRouteRun struct {
	used  atomic.Bool
	route *TunnelRoute
	pair  *RelayPairRun
}

func (r *TunnelRoute) ClaimRun(service resourcev4.Reference) (*TunnelRouteRun, error) {
	return r.claimRun(service, true)
}
func (r *TunnelRoute) claimRun(service resourcev4.Reference, hosted bool) (*TunnelRouteRun, error) {
	if r == nil {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.started || r.pair == nil {
		return nil, cryptov4.ErrTransition
	}
	if err := r.reservation.Check(); err != nil {
		return nil, err
	}
	run, err := r.pair.claimRun(service, hosted)
	if err != nil {
		return nil, err
	}
	r.started, r.running = true, true
	r.runner.route, r.runner.pair = r, run
	return &r.runner, nil
}
func (r *TunnelRoute) Run(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	run, err := r.claimRun(resourcev4.Reference{}, false)
	if err != nil {
		return err
	}
	return run.Run(ctx)
}
func (r *TunnelRoute) RunHosted(ctx context.Context, service resourcev4.Reference) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	run, err := r.ClaimRun(service)
	if err != nil {
		return err
	}
	return run.Run(ctx)
}
func (run *TunnelRouteRun) Run(ctx context.Context) (err error) {
	if run == nil || run.route == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if !run.used.CompareAndSwap(false, true) {
		return cryptov4.ErrTransition
	}
	r := run.route
	local, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	r.cancel = cancel
	closed := r.closed
	r.mu.Unlock()
	if closed {
		cancel()
	}
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		r.Close()
		// Both actual provider/authentication methods must return before this
		// admitted invocation can settle. Cancellation never refunds their backing.
		for side := 0; side < 2; side++ {
			if e := <-r.results; e != nil {
				err = errors.Join(err, e)
			}
		}
		r.mu.Lock()
		r.running = false
		r.cancel = nil
		close(r.settled)
		r.mu.Unlock()
	}()
	for side := 0; side < 2; side++ {
		go r.prepareHop(local, side)
	}
	err = run.pair.Run(local)
	returned = true
	return err
}

func (r *TunnelRoute) prepareHop(ctx context.Context, side int) {
	var err error
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		if err != nil {
			r.Close()
		}
		r.results <- err
	}()
	err = func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.c.Pair.PreparationDeadline.Check(); err != nil {
			return err
		}
		prepared, err := r.c.Prepare[side](ctx, r.c.Carriers[side])
		r.mu.Lock()
		r.prepared[side] = prepared
		closed := r.closed
		r.mu.Unlock()
		if err != nil {
			return err
		}
		if prepared == nil {
			return cryptov4.ErrConfiguration
		}
		if closed {
			return resourcev4.ErrClosed
		}
		if err = r.checkPrepared(side, prepared); err != nil {
			return err
		}
		hop, err := NewRelayHop(ctx, r.c.Hops[side], prepared, r.hopRefs[side], r.dependencies)
		r.mu.Lock()
		r.hops[side] = hop
		closed = r.closed
		r.mu.Unlock()
		if err != nil {
			return err
		}
		if hop == nil {
			return cryptov4.ErrConfiguration
		}
		if closed {
			hop.Close()
			return resourcev4.ErrClosed
		}
		return hop.Authenticate(r.c.Store, r.c.Table)
	}()
	returned = true
}

func (r *TunnelRoute) checkPrepared(side int, p *PreparedCarrier) error {
	if p == nil || p.preparedCarrier == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c := r.c.Carriers[side]
	if !p.relay || p.deadline != c.Deadline || p.environment != c.Environment || p.admission != nil || p.activated || p.binding.Candidate != c.Candidate || p.binding.Attempt != c.Attempt || p.binding.Session != c.Session || p.binding.Role != c.Role {
		return resourcev4.ErrOwner
	}
	if err := r.carrierRefs[side].CheckBorrowedFrom(p.reservation); err != nil {
		return err
	}
	return p.checkLocked()
}

func (r *TunnelRoute) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}
	pair, prepared := r.pair, r.prepared
	if !r.started && r.settled != nil {
		select {
		case <-r.settled:
		default:
			close(r.settled)
		}
	}
	r.mu.Unlock()
	if pair != nil {
		pair.Close()
	}
	for _, p := range prepared {
		if p != nil {
			_ = p.Close()
		}
	}
}

func (r *TunnelRoute) WaitCleanup(ctx context.Context) error {
	if r == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.cleaned {
		r.mu.Unlock()
		return nil
	}
	if !r.closed || r.cleaning {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	r.cleaning = true
	settled := r.settled
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.cleaning = false; r.mu.Unlock() }()
	select {
	case <-settled:
	case <-ctx.Done():
		return ctx.Err()
	}
	if r.pair != nil {
		if err := r.pair.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	for side, p := range r.prepared {
		// Adopted carriers belong to their registered hop/pair. An early failed
		// prepare or constructor retains this same original physical owner here.
		if p != nil && r.hops[side] == nil {
			_ = p.Close()
			if err := p.WaitCleanup(ctx); err != nil {
				return err
			}
			if err := p.Retire(); err != nil {
				return err
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, maps := range r.maps {
		for _, m := range maps {
			if m != nil {
				m.Release()
			}
		}
	}
	for _, ref := range r.carrierRefs {
		ref.Release()
	}
	for _, ref := range r.refs {
		ref.Release()
	}
	r.table.Release()
	r.store.Release()
	r.shared.Release()
	r.reservation.Release()
	r.c = TunnelRouteConfig{}
	r.maps = [2][3]*protocolv4.SignedMap{}
	r.codecs = [2][3]*protocolv4.SignedMapCodec{}
	r.refs = [15]resourcev4.Reference{}
	r.hops = [2]*RelayHop{}
	r.prepared = [2]*PreparedCarrier{}
	r.pair = nil
	r.carrierRefs = [2]resourcev4.Reference{}
	r.dependencies = resourcev4.Reference{}
	r.table, r.store, r.shared, r.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	r.cleaned = true
	close(r.done)
	return nil
}

func (*TunnelRoute) String() string               { return "Flowersec.TunnelRoute" }
func (*TunnelRoute) GoString() string             { return "Flowersec.TunnelRoute" }
func (*TunnelRoute) MarshalJSON() ([]byte, error) { return []byte(`"Flowersec.TunnelRoute"`), nil }
