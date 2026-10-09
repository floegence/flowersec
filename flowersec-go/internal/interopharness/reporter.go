package interopharness

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type constructionFailure struct{ err error }

// Reporter owns engineering authority construction and the real advancing local
// clock. The local envelope is an explicit authority test input, never a time
// assertion received from an untrusted peer or a deployment continuity claim.
type Reporter struct {
	mu                                          sync.Mutex
	epoch                                       uint64
	clock                                       *timev4.Clock
	cleanup                                     []*reporterCleanup
	owners                                      []*reporterOwner
	failures                                    []error
	artifactDir                                 string
	closed                                      bool
	finished                                    chan struct{}
	lease, attempt                              [16]byte
	bootstrap                                   protocolv4.NamespaceBootstrapProvider
	rootPin                                     *protocolv4.NamespaceTrustRoot
	ApplicationProfile                          string
	MaxStreams                                  uint32
	ListenerConnections, AcceptedRoutePositions uint16
	OperationDeadlineMS                         uint64
	ActivationWindowMS                          uint64
	RouteHost                                   string
	candidateID                                 [16]byte
	directRoutes                                [][]byte
	tunnel                                      *sessionv4.EngineeringTunnelRecipe
	originalPoolDeployment                      bool
	originalLiveDeployment                      bool
}

type reporterOwner struct {
	close func()
	wait  func(context.Context) error
}

func NewReporter(artifactDir string) (*Reporter, error) {
	if artifactDir == "" || !filepath.IsAbs(artifactDir) {
		return nil, errors.New("engineering artifact directory must be absolute")
	}
	if err := os.MkdirAll(artifactDir, 0700); err != nil {
		return nil, err
	}
	started := time.Now()
	r := &Reporter{epoch: uint64(started.UnixMilli()), artifactDir: artifactDir}
	if _, err := rand.Read(r.lease[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(r.attempt[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(r.candidateID[:]); err != nil {
		return nil, err
	}
	var incarnation [16]byte
	if _, err := rand.Read(incarnation[:]); err != nil {
		return nil, err
	}
	clock, err := newReporterClock(started, incarnation)
	if err != nil {
		return nil, err
	}
	r.clock = clock
	r.Cleanup(clock.Close)
	return r, nil
}

func newReporterClock(started time.Time, incarnation [16]byte) (*timev4.Clock, error) {
	return newReporterClockFromSources(func() time.Duration { return time.Since(started) }, time.Now, incarnation)
}

// A Time's wall and monotonic components need not be sampled atomically. Use
// the independent local wall read only within its measured monotonic bracket;
// construction delay must not become a permanent offset between peer clocks.
func newReporterClockFromSources(elapsed func() time.Duration, wall func() time.Time, incarnation [16]byte) (*timev4.Clock, error) {
	const uncertainty = 2 * time.Millisecond
	const attempts = 16
	var offset int64
	var after time.Duration
	paired := false
	for range attempts {
		before := elapsed()
		wallNanos := wall().UnixNano()
		after = elapsed()
		if before < 0 || after < before || after > 30*time.Minute || wallNanos < int64(after) {
			return nil, timev4.ErrUnavailable
		}
		if after-before > uncertainty {
			continue
		}
		// UTC minus elapsed lies in [wall-after, wall-before]. Keep its
		// nanosecond phase before rounding, so the same 2 ms envelope covers
		// every later integer tick without repeated quantization expansion.
		offset = wallNanos - int64(after)
		paired = true
		break
	}
	if !paired {
		return nil, timev4.ErrUnavailable
	}
	epoch := uint64(offset / int64(time.Millisecond))
	phase := time.Duration(offset % int64(time.Millisecond))
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 1800000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		current := elapsed()
		if current < after || current > 30*time.Minute {
			return timev4.Tick{}, timev4.ErrUnavailable
		}
		return timev4.Tick{Milliseconds: uint64((current + phase) / time.Millisecond), Incarnation: incarnation}, nil
	})
	if err != nil {
		return nil, err
	}
	mark, err := clock.Monotonic()
	if err == nil {
		lower := epoch + mark.Milliseconds
		err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: lower, UpperMS: lower + uint64(uncertainty/time.Millisecond)})
	}
	if err != nil {
		clock.Close()
		return nil, err
	}
	return clock, nil
}
func (r *Reporter) AuthorityEpochMS() uint64            { return r.epoch }
func (r *Reporter) AuthorityActivationWindowMS() uint64 { return r.ActivationWindowMS }
func (r *Reporter) AuthorityClock() *timev4.Clock       { return r.clock }
func (*Reporter) Helper()                               {}
func (*Reporter) Fatal(values ...any) {
	if len(values) == 1 {
		if err, ok := values[0].(error); ok {
			panic(constructionFailure{err})
		}
	}
	panic(constructionFailure{fmt.Errorf("%s", fmt.Sprint(values...))})
}
func (r *Reporter) Error(values ...any) {
	r.mu.Lock()
	r.failures = append(r.failures, fmt.Errorf("%s", fmt.Sprint(values...)))
	r.mu.Unlock()
}

type reporterCleanup struct{ callback func() }

func (r *Reporter) Cleanup(f func()) { r.registerCleanup(f) }

// Owner records the concrete physical owner at the point it is acquired. It
// remains available after a bounded wait fails, so callers can retry the same
// owner instead of relying on a one-shot diagnostic cleanup callback.
func (r *Reporter) Owner(close func(), wait func(context.Context) error) {
	if close == nil || wait == nil {
		return
	}
	r.mu.Lock()
	r.owners = append(r.owners, &reporterOwner{close: close, wait: wait})
	r.mu.Unlock()
}
func (r *Reporter) CloseOwners() {
	r.mu.Lock()
	owners := append([]*reporterOwner(nil), r.owners...)
	r.mu.Unlock()
	for _, owner := range owners {
		if owner != nil && owner.close != nil {
			owner.close()
		}
	}
}
func (r *Reporter) WaitOwners(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	owners := append([]*reporterOwner(nil), r.owners...)
	r.mu.Unlock()
	var result error
	for _, owner := range owners {
		if owner != nil && owner.wait != nil {
			result = errors.Join(result, owner.wait(ctx))
		}
	}
	return result
}
func (r *Reporter) registerCleanup(f func()) func() {
	entry := &reporterCleanup{callback: f}
	r.mu.Lock()
	if r.closed && r.finished != nil {
		select {
		case <-r.finished:
			r.mu.Unlock()
			f()
			return func() {}
		default:
		}
	}
	r.cleanup = append(r.cleanup, entry)
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for index, current := range r.cleanup {
			if current == entry {
				copy(r.cleanup[index:], r.cleanup[index+1:])
				last := len(r.cleanup) - 1
				r.cleanup[last] = nil
				r.cleanup = r.cleanup[:last]
				return
			}
		}
	}
}
func (r *Reporter) TempDir() string {
	path, err := os.MkdirTemp(r.artifactDir, "authority-")
	if err != nil {
		r.Fatal(err)
	}
	r.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			r.Error(err)
		}
	})
	return path
}
func (r *Reporter) Close() error {
	r.mu.Lock()
	if r.closed {
		done := r.finished
		r.mu.Unlock()
		<-done
		r.mu.Lock()
		result := errors.Join(r.failures...)
		r.mu.Unlock()
		return result
	}
	r.closed = true
	r.finished = make(chan struct{})
	r.mu.Unlock()
	for {
		r.mu.Lock()
		if len(r.cleanup) == 0 {
			close(r.finished)
			result := errors.Join(r.failures...)
			r.mu.Unlock()
			return result
		}
		last := len(r.cleanup) - 1
		callback := r.cleanup[last]
		r.cleanup[last] = nil
		r.cleanup = r.cleanup[:last]
		r.mu.Unlock()
		callback.callback()
	}
}

func construct[T any](r *Reporter, build func() T) (result T, err error) {
	defer func() {
		if value := recover(); value != nil {
			if failure, ok := value.(constructionFailure); ok {
				err = failure.err
				return
			}
			panic(value)
		}
	}()
	return build(), nil
}

func (r *Reporter) AuthorityOriginalPoolDeployment() bool { return r.originalPoolDeployment }
func (r *Reporter) AuthorityOriginalLiveDeployment() bool { return r.originalLiveDeployment }

func (r *Reporter) AuthorityLeaseID() [16]byte   { return r.lease }
func (r *Reporter) AuthorityAttemptID() [16]byte { return r.attempt }
func (r *Reporter) AuthorityBootstrapProvider() protocolv4.NamespaceBootstrapProvider {
	return r.bootstrap
}

// The shared namespace admits both endpoints' eight concurrent RPC results,
// their independent delivery floors and the source/Session subscriptions.
func (r *Reporter) AuthorityNamespaceSubscribers() uint32                  { return 64 }
func (r *Reporter) AuthorityNamespaceRoot() *protocolv4.NamespaceTrustRoot { return r.rootPin }

func (r *Reporter) AuthorityApplicationProfile() string {
	if r.ApplicationProfile == "" {
		return "transport"
	}
	return r.ApplicationProfile
}

// ForkAuthority issues an independent lease/attempt in the same explicit local
// authority time domain. It shares the original clock without owning Close.
func (r *Reporter) ForkAuthority() (*Reporter, error) {
	child, err := r.detachedAuthority()
	if err != nil {
		return nil, err
	}
	detach := r.registerCleanup(func() { r.ErrorIf(child.Close()) })
	child.Cleanup(detach)
	return child, nil
}
func (r *Reporter) detachedAuthority() (*Reporter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("original authority reporter is closed")
	}
	child := &Reporter{epoch: r.epoch, clock: r.clock, artifactDir: r.artifactDir, ApplicationProfile: r.ApplicationProfile, MaxStreams: r.MaxStreams, ListenerConnections: r.ListenerConnections, AcceptedRoutePositions: r.AcceptedRoutePositions, OperationDeadlineMS: r.OperationDeadlineMS, ActivationWindowMS: r.ActivationWindowMS, RouteHost: r.RouteHost, candidateID: r.candidateID, directRoutes: r.directRoutes, tunnel: r.tunnel}
	if _, err := rand.Read(child.lease[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(child.attempt[:]); err != nil {
		return nil, err
	}
	return child, nil
}

func (r *Reporter) AuthorityMaxStreams() uint32  { return r.MaxStreams }
func (r *Reporter) AuthorityCarrierHost() string { return r.RouteHost }

func (r *Reporter) AuthorityCandidateID() [16]byte  { return r.candidateID }
func (r *Reporter) AuthorityDirectRoutes() [][]byte { return r.directRoutes }

// ForkEndpointAuthority fixes a distinct original listener identity while
// preserving the explicit authority clock and namespace publication geometry.
func (r *Reporter) ForkEndpointAuthority() (*Reporter, error) {
	child, err := r.detachedAuthority()
	if err != nil {
		return nil, err
	}
	if _, err = rand.Read(child.candidateID[:]); err != nil {
		return nil, err
	}
	detach := r.registerCleanup(func() { r.ErrorIf(child.Close()) })
	child.Cleanup(detach)
	return child, nil
}

// SetTunnelRecipe fixes the explicit route and independent relay policy before
// constructing this authority's original signed material. It is immutable for
// that authority; independent forks carry their own endpoint lease/attempt.
func (r *Reporter) SetTunnelRecipe(recipe sessionv4.EngineeringTunnelRecipe) error {
	defer clear(recipe.RelayIdentitySeed[:])
	defer clear(recipe.GrantIssuerSeed[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.tunnel != nil || len(r.directRoutes) != 0 || len(recipe.Route) == 0 {
		return errors.New("original engineering route selection is already fixed or unavailable")
	}
	copyRecipe := recipe
	copyRecipe.Route = append([]byte(nil), recipe.Route...)
	// Reporter owns the original recipe; readers receive detached value copies.
	r.cleanup = append(r.cleanup, &reporterCleanup{callback: func() { clear(copyRecipe.RelayIdentitySeed[:]); clear(copyRecipe.GrantIssuerSeed[:]) }})
	r.tunnel = &copyRecipe
	return nil
}
func (r *Reporter) AuthorityTunnelRecipe() *sessionv4.EngineeringTunnelRecipe {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tunnel == nil {
		return nil
	}
	recipe := *r.tunnel
	recipe.Route = append([]byte(nil), r.tunnel.Route...)
	return &recipe
}
