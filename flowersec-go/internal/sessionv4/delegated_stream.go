package sessionv4

import (
	"context"
	"errors"
	"net"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

var ErrDelegatedServe = errors.New("sessionv4: delegated service failed")
var ErrDelegatedServeExit = errors.New("sessionv4: delegated service exited without returning")

// DelegatedStreamServe receives only the original narrow endpoint and its
// cancellation lifetime. The trusted runtime declaration must cover the full
// external execution, allocations and descendants; return must join them.
// The SDK cannot inspect or forcibly stop hidden third-party work. An arbitrary
// callback declaring a vector is not a resource qualification of that runtime.
type DelegatedStreamServe func(context.Context, net.Conn) error

type DelegatedStreamOptions struct {
	Connection      StreamConnOptions
	RuntimeBytes    uint64
	ExternalRuntime resourcev4.Vector
}

// DelegatedStreamService binds an external raw protocol implementation to the
// same original kind registry and service slots as delegated HTTP. Setup has
// ordinary invocation authority; the returned Serve does not inherit it.
type DelegatedStreamService struct {
	Options DelegatedStreamOptions
	Setup   func(context.Context, any, []byte) (DelegatedStreamServe, error)
}

func DelegatedStreamCharge(options DelegatedStreamOptions) (resourcev4.Vector, error) {
	if options.RuntimeBytes == 0 || options.ExternalRuntime[resourcev4.ProviderBytes] == 0 || options.ExternalRuntime[resourcev4.Tasks] == 0 || options.ExternalRuntime[resourcev4.WorkSlots] == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if _, err := StreamConnCharge(options.Connection); err != nil {
		return resourcev4.Vector{}, err
	}
	// The interruption worker is SDK work; the Serve task belongs to the
	// explicitly declared external vector, which includes that actual task.
	fixed := uint64(unsafe.Sizeof(DelegatedStream{})) + uint64(unsafe.Sizeof(connExternalCleanup{}))
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: fixed, resourcev4.Items: 2, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: options.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(options.ExternalRuntime)
}

type DelegatedStream struct {
	mu                        sync.Mutex
	conn                      *StreamConn
	reservation, dependencies resourcev4.Reference
	external                  *connExternalCleanup
	workers                   uint8
	serveDone                 chan struct{}
	context                   context.Context
	cancel                    context.CancelFunc
	serve                     DelegatedStreamServe
}

// StartDelegatedStream consumes preadmitted external service and connection
// owners. No external function runs inside an admission or I/O gate. Normal
// Serve return starts this original connection's authenticated close; failures
// and cancellation use its original abort. The connection's compound cleanup
// continues to own a noncooperative external callback until actual return.
func StartDelegatedStream(ctx context.Context, owner *StreamOwnership, serve DelegatedStreamServe, options DelegatedStreamOptions, reservation, connectionReservation, dependencies resourcev4.Reference) (*DelegatedStream, error) {
	if ctx == nil || owner == nil || serve == nil || reservation == connectionReservation || reservation == dependencies || connectionReservation == dependencies {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	charge, err := DelegatedStreamCharge(options)
	if err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(connectionReservation); err != nil {
		return nil, err
	}
	owned, shared, external, err := prepareConnExternal(reservation, dependencies, charge)
	if err != nil {
		return nil, err
	}
	s := &DelegatedStream{reservation: owned, dependencies: shared, external: external, workers: 2, serveDone: make(chan struct{}), serve: serve}
	s.context, s.cancel = context.WithCancel(ctx)
	s.conn, err = owner.asConn(ctx, options.Connection, connectionReservation, external)
	if err != nil {
		s.cancel()
		external.backing.Release()
		external.dependencies.Release()
		owned.Release()
		shared.Release()
		return nil, err
	}
	go s.run()
	go s.interrupt()
	return s, nil
}

func (s *DelegatedStream) Abort()                                            { s.conn.Abort() }
func (s *DelegatedStream) Result() (protocolv4.V4CloseResult, uint64, error) { return s.conn.Result() }
func (s *DelegatedStream) CleanupStatus() protocolv4.V4CleanupStatus         { return s.conn.CleanupStatus() }
func (s *DelegatedStream) WaitCleanup(ctx context.Context) (protocolv4.V4CloseResult, error) {
	return s.conn.WaitCleanup(ctx)
}

func (s *DelegatedStream) run() {
	defer s.exitWorker()
	defer close(s.serveDone)
	returned := false
	defer func() {
		_ = recover()
		if !returned {
			s.fail(ErrDelegatedServeExit)
		}
		s.external.callbacks.Store(0)
	}()
	c := s.conn
	c.mu.Lock()
	err := s.reservation.Check()
	if err == nil {
		err = s.dependencies.Check()
	}
	if err == nil {
		err = s.context.Err()
	}
	if err == nil && c.closed {
		err = net.ErrClosed
	}
	if err == nil {
		err = c.owner.enterCallback()
	}
	if err == nil {
		s.external.callbacks.Store(1)
	}
	c.mu.Unlock()
	if err != nil {
		returned = true
		s.fail(err)
		return
	}
	err = s.serve(s.context, c)
	returned = true
	if err != nil {
		s.fail(ErrDelegatedServe)
	} else {
		_ = c.Close()
	}
}

func (s *DelegatedStream) fail(err error) {
	s.conn.mu.Lock()
	s.conn.closeLocked(err)
	s.conn.mu.Unlock()
}

func (s *DelegatedStream) interrupt() {
	defer s.exitWorker()
	select {
	case <-s.conn.aborting:
	case <-s.serveDone:
	}
	// Cancel only external execution. On normal return the connection still
	// owns accepted output and must retain its original parent until Finish.
	s.cancel()
}

func (s *DelegatedStream) exitWorker() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workers--
	if s.workers != 0 {
		return
	}
	s.serve, s.context, s.cancel = nil, nil, nil
	s.reservation.Release()
	s.dependencies.Release()
	s.reservation, s.dependencies = resourcev4.Reference{}, resourcev4.Reference{}
	close(s.external.done)
}
