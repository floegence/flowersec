package controlplane_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type controlContinuity struct{ identity ledgerv4.SQLiteIdentity }

func (h controlContinuity) Check(identity ledgerv4.SQLiteIdentity, _ uint64, _ bool) error {
	if identity != h.identity {
		return ledgerv4.ErrFenced
	}
	return nil
}

type controlResources struct {
	t           *testing.T
	root        *resourcev4.Root
	clock       *timev4.Clock
	environment resourcev4.Reference
	serial      byte
}

func newControlResources(t *testing.T) *controlResources {
	t.Helper()
	c := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 64, ReferenceSlots: 256}
	for i := range c.Limit {
		c.Limit[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(c)
	if err != nil {
		t.Fatal(err)
	}
	f := &controlResources{t: t, root: root}
	t.Cleanup(func() {
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("control-plane owner retained resources", root.Snapshot())
		}
	})
	f.environment = f.reserve(resourcev4.Vector{resourcev4.SDKBytes: 4096})
	f.clock, err = timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Numerator: 1, Denominator: 1000000, QuantizationMS: 1}, MaxWidthMS: 1000, MaxAgeMS: 60000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) { return timev4.Tick{Milliseconds: 1, Incarnation: [16]byte{1}}, nil })
	if err != nil {
		t.Fatal(err)
	}
	mark, err := f.clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1000, UpperMS: 1001}); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *controlResources) reserve(charge resourcev4.Vector) resourcev4.Reference {
	f.t.Helper()
	f.serial++
	ref, err := f.root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{f.serial}, Backing: [16]byte{f.serial}, Kind: 1}, charge)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(ref.Release)
	return ref
}
func (f *controlResources) store() (*ledgerv4.SQLiteStore, ledgerv4.SQLiteIdentity, uint32) {
	f.t.Helper()
	l := ledgerv4.SQLiteLimits{MaxPages: 128, MaxRecords: 16, MaxRecordBytes: 65536, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	cost, err := ledgerv4.SQLiteBackingCharge(l)
	if err != nil {
		f.t.Fatal(err)
	}
	path := filepath.Join(f.t.TempDir(), "control.db")
	backing, err := ledgerv4.NewSQLiteBacking(path, l, f.reserve(cost), f.environment)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		backing.Close()
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				f.t.Error(err)
			}
		}
		if err := backing.ReleaseRemoved(); err != nil {
			f.t.Error(err)
		}
	})
	identity := ledgerv4.SQLiteIdentity{Authority: "control.example", StoreID: [32]byte{7}, Generation: 1}
	cost, err = ledgerv4.SQLiteStoreCharge(l)
	if err != nil {
		f.t.Fatal(err)
	}
	store, err := ledgerv4.CreateSQLite(context.Background(), backing, identity, controlContinuity{identity}, f.reserve(cost), f.environment)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		store.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := store.WaitCleanup(ctx); err != nil {
			f.t.Error(err)
		}
		if err := store.Retire(); err != nil {
			f.t.Error(err)
		}
	})
	return store, identity, l.MaxRecordBytes
}

type controlReadAccess struct {
	identity         ledgerv4.SQLiteIdentity
	denied           atomic.Bool
	calls            atomic.Int32
	entered, release chan struct{}
}

func (a *controlReadAccess) Target(identity ledgerv4.SQLiteIdentity) (ledgerv4.LiveSpendReadTarget, error) {
	a.calls.Add(1)
	if a.entered != nil {
		close(a.entered)
		<-a.release
	}
	if identity != a.identity || a.denied.Load() {
		return ledgerv4.LiveSpendReadTarget{}, ledgerv4.ErrDenied
	}
	return ledgerv4.LiveSpendReadTarget{Tenant: "tenant", Audience: "service", Issuer: [16]byte{1}, Lease: [16]byte{2}, Attempt: [16]byte{3}, ClientIdentity: [32]byte{4}, RequestDigest: [32]byte{5}}, nil
}
func (*controlReadAccess) CheckMaterial(ledgerv4.SQLiteIdentity, ledgerv4.LiveSpendReadTarget, *protocolv4.SignedMap) error {
	return ledgerv4.ErrDenied
}
func (*controlReadAccess) CheckClientGrant(ledgerv4.SQLiteIdentity, ledgerv4.LiveSpendReadTarget, *protocolv4.SignedMap) error {
	return ledgerv4.ErrDenied
}

func newPublicSpendService(t *testing.T, f *controlResources, c controlplane.SpendReceiptServiceConfig) *controlplane.SpendReceiptService {
	t.Helper()
	a, b, err := controlplane.SpendReceiptServiceCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	service, err := controlplane.NewSpendReceiptService(c, f.reserve(a), f.reserve(b), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		service.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	return service
}

func TestV4SpendReceiptAuthenticatesMissingHistoryAndBoundsOutput(t *testing.T) {
	f := newControlResources(t)
	store, identity, recordBytes := f.store()
	c := controlplane.SpendReceiptServiceConfig{Store: store, Clock: f.clock, MaxRecordBytes: recordBytes, RequestsPerMinute: 60, Burst: 20, WorkMS: 1000, RuntimeBytes: 65536}
	service := newPublicSpendService(t, f, c)
	deadline, err := timev4.NewDeadline(f.clock, 10000)
	if err != nil {
		t.Fatal(err)
	}
	access := &controlReadAccess{identity: identity}
	before := f.root.Snapshot()
	if receipt, err := service.QuerySpendReceipt(context.Background(), access, deadline); err != controlplane.SpendQueryFailure("history_unknown") || receipt != (controlplane.SpendReceipt{}) {
		t.Fatal("missing durable history granted a receipt", receipt, err)
	}
	access.denied.Store(true)
	if _, err := service.QuerySpendReceipt(context.Background(), access, deadline); err != controlplane.SpendQueryFailure("permission_denied") {
		t.Fatal("missing history bypassed access policy", err)
	}
	output := bytes.Repeat([]byte{0xa5}, 70)
	if n, err := service.QuerySpendReceiptBytes(context.Background(), access, deadline, output); n != 0 || err != controlplane.SpendQueryFailure("permission_denied") {
		t.Fatal(n, err)
	}
	if !bytes.Equal(output[:61], make([]byte, 61)) || !bytes.Equal(output[61:], bytes.Repeat([]byte{0xa5}, 9)) {
		t.Fatal("failure did not clear exactly the owned receipt buffer")
	}
	if after := f.root.Snapshot(); after != before {
		t.Fatal("refused reads leaked admission", before, after)
	}
	service.Close()
	if err := service.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := access.calls.Load()
	if _, err := service.QuerySpendReceipt(context.Background(), access, deadline); err != controlplane.SpendQueryFailure("unavailable") || access.calls.Load() != calls {
		t.Fatal("closed service reached authentication", err)
	}

	a, b, err := controlplane.V4LiveRelayRegistrationServiceCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := controlplane.NewV4LiveRelayRegistrationService(c, f.reserve(a), f.reserve(b), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		relay.Close()
		if err := relay.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
	})
	// The public constructor must force tunnel admission even if the caller
	// supplied the default false flag; authorization still precedes capture.
	if receipt, err := relay.CaptureRelayLeg(context.Background(), access, deadline, identity, nil, 0, resourcev4.Reference{}, f.environment); receipt != nil || err != controlplane.SpendQueryFailure("permission_denied") {
		t.Fatal("relay capture bypassed authentication", receipt, err)
	}
}

func TestV4SpendCloseRetainsOriginalAuthenticationTail(t *testing.T) {
	f := newControlResources(t)
	store, identity, recordBytes := f.store()
	c := controlplane.SpendReceiptServiceConfig{Store: store, Clock: f.clock, MaxRecordBytes: recordBytes, RequestsPerMinute: 60, Burst: 20, WorkMS: 1000, RuntimeBytes: 65536}
	service := newPublicSpendService(t, f, c)
	deadline, err := timev4.NewDeadline(f.clock, 10000)
	if err != nil {
		t.Fatal(err)
	}
	access := &controlReadAccess{identity: identity, entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-access.release:
		default:
			close(access.release)
		}
	}()
	done := make(chan error, 1)
	go func() { _, err := service.QuerySpendReceipt(context.Background(), access, deadline); done <- err }()
	select {
	case <-access.entered:
	case err := <-done:
		t.Fatal("authentication not entered", err)
	case <-time.After(2 * time.Second):
		t.Fatal("authentication not entered")
	}
	before := f.root.Snapshot()
	service.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := service.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup completed before original callback", err)
	}
	if after := f.root.Snapshot(); after != before {
		t.Fatal("Close refunded a live authentication tail", before, after)
	}
	if _, err := service.QuerySpendReceipt(context.Background(), access, deadline); err != controlplane.SpendQueryFailure("unavailable") || access.calls.Load() != 1 {
		t.Fatal("Close dispatched another authentication", err)
	}
	close(access.release)
	select {
	case err := <-done:
		if err != controlplane.SpendQueryFailure("cancelled") {
			t.Fatal("cancelled authentication published a result", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authentication did not finish")
	}
	if err := service.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestV4PublicReadServicesChargeCompleteOwner(t *testing.T) {
	for _, tunnel := range []bool{false, true} {
		t.Run(map[bool]string{false: "spend", true: "relay"}[tunnel], func(t *testing.T) {
			f := newControlResources(t)
			store, _, recordBytes := f.store()
			c := controlplane.SpendReceiptServiceConfig{Store: store, Clock: f.clock, MaxRecordBytes: recordBytes, RequestsPerMinute: 60, Burst: 20, WorkMS: 1000, RuntimeBytes: 65536, Tunnel: tunnel}
			inner, read, err := controlv4.LiveSpendServiceCharges(c)
			if err != nil {
				t.Fatal(err)
			}
			wrapper := uint64(unsafe.Sizeof(controlplane.SpendReceiptService{}))
			if tunnel {
				wrapper = uint64(unsafe.Sizeof(controlplane.V4LiveRelayRegistrationService{}))
			}
			required, err := inner.Add(resourcev4.Vector{resourcev4.SDKBytes: wrapper})
			if err != nil {
				t.Fatal(err)
			}
			for _, short := range []bool{true, false} {
				cost := required
				if short {
					cost[resourcev4.SDKBytes]--
				}
				before := f.root.Snapshot()
				owner, reader := f.reserve(cost), f.reserve(read)
				var service interface {
					Close()
					WaitCleanup(context.Context) error
				}
				if tunnel {
					s, e := controlplane.NewV4LiveRelayRegistrationService(c, owner, reader, f.environment)
					err = e
					if s != nil {
						service = s
					}
				} else {
					s, e := controlplane.NewSpendReceiptService(c, owner, reader, f.environment)
					err = e
					if s != nil {
						service = s
					}
				}
				if service != nil {
					owner.Release()
					reader.Release()
					if f.root.Snapshot().Charged[resourcev4.SDKBytes] < before.Charged[resourcev4.SDKBytes]+required[resourcev4.SDKBytes]+read[resourcev4.SDKBytes] {
						t.Error("stale caller reference refunded admitted owner")
					}
					service.Close()
					if cleanup := service.WaitCleanup(context.Background()); cleanup != nil {
						t.Fatal(cleanup)
					}
				}
				if short {
					if err != controlplane.SpendQueryFailure("resource_exhausted") || service != nil {
						t.Error("public owner was admitted without its complete wrapper charge", err)
					}
					if owner.Check() != nil || reader.Check() != nil {
						t.Error("short admission consumed caller reservation")
					}
				} else if err != nil || service == nil {
					t.Fatal("complete charge refused", err)
				}
				owner.Release()
				reader.Release()
				if after := f.root.Snapshot(); after != before {
					t.Fatal("service lifecycle retained a charge", before, after)
				}
			}
			var advertised, advertisedRead resourcev4.Vector
			if tunnel {
				advertised, advertisedRead, err = controlplane.V4LiveRelayRegistrationServiceCharges(c)
			} else {
				advertised, advertisedRead, err = controlplane.SpendReceiptServiceCharges(c)
			}
			if err != nil || advertised != required || advertisedRead != read {
				t.Fatal("public charge omits wrapper or changes read owner", advertised, required, err)
			}
		})
	}
}
