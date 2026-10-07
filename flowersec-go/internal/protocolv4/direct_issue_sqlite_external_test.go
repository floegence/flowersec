package protocolv4_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type directSQLiteHost struct {
	identity ledgerv4.SQLiteIdentity
	denied   bool
	epoch    uint64
}

func (h *directSQLiteHost) Check(i ledgerv4.SQLiteIdentity, epoch uint64, _ bool) error {
	if i != h.identity {
		return ledgerv4.ErrFenced
	}
	if epoch > h.epoch {
		h.epoch = epoch
	}
	return nil
}
func (h *directSQLiteHost) CheckDirectIssueShare(i ledgerv4.SQLiteIdentity, p protocolv4.DirectIssuePolicyLimits, count uint32, size uint64) error {
	if h.denied || i != h.identity || p.Namespace.Tenant != "tenant-1" || count == 0 || size > p.MaxStateBytes {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (h *directSQLiteHost) AuthorizeDirectIssue(_ context.Context, i ledgerv4.SQLiteIdentity, r protocolv4.DirectIssueRequest, f protocolv4.DirectIssueFacts) (ledgerv4.SQLiteDirectIssueAccess, error) {
	if h.denied || i != h.identity || !bytes.Equal(r.Authentication, []byte("authenticated host request")) || f.NamespaceCount != 1 {
		return nil, ledgerv4.ErrDenied
	}
	return &directSQLiteAccess{host: h}, nil
}

type directSQLiteAccess struct {
	host   *directSQLiteHost
	closed bool
}

func (a *directSQLiteAccess) Check(ctx context.Context) error {
	if a.closed || a.host.denied {
		return ledgerv4.ErrDenied
	}
	return ctx.Err()
}
func (a *directSQLiteAccess) Close() { a.closed = true }

type directSQLiteFixture struct {
	t       *testing.T
	h       *protocolv4.DirectIssueSQLiteTestHarness
	host    *directSQLiteHost
	limits  ledgerv4.SQLiteLimits
	backing *ledgerv4.SQLiteBacking
	stores  []*ledgerv4.SQLiteStore
}

func newDirectSQLiteFixture(t *testing.T) *directSQLiteFixture {
	h := protocolv4.NewDirectIssueSQLiteTestHarness(t)
	f := &directSQLiteFixture{t: t, h: h, host: &directSQLiteHost{identity: ledgerv4.SQLiteIdentity{Authority: "direct.reference", StoreID: [32]byte{21}, Generation: 1}}, limits: ledgerv4.SQLiteLimits{MaxPages: 256, MaxRecords: 16, MaxRecordBytes: 4096, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}}
	charge, err := ledgerv4.SQLiteBackingCharge(f.limits)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "direct-issuer.db")
	f.backing, err = ledgerv4.NewSQLiteBacking(path, f.limits, h.Reserve(charge), h.Environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range f.stores {
			closeDirectSQLite(t, s)
		}
		f.backing.Close()
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		if err := f.backing.ReleaseRemoved(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func closeDirectSQLite(t *testing.T, s *ledgerv4.SQLiteStore) {
	t.Helper()
	s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(); err != nil {
		t.Fatal(err)
	}
}

func (f *directSQLiteFixture) open(create bool) *ledgerv4.SQLiteStore {
	f.t.Helper()
	charge, err := ledgerv4.SQLiteStoreCharge(f.limits)
	if err != nil {
		f.t.Fatal(err)
	}
	var s *ledgerv4.SQLiteStore
	if create {
		s, err = ledgerv4.CreateSQLite(context.Background(), f.backing, f.host.identity, f.host, f.h.Reserve(charge), f.h.Environment)
	} else {
		s, err = ledgerv4.OpenSQLite(context.Background(), f.backing, f.host.identity, f.host, f.h.Reserve(charge), f.h.Environment)
	}
	if err != nil {
		f.t.Fatal(err)
	}
	f.stores = append(f.stores, s)
	return s
}

func (f *directSQLiteFixture) config(outstanding uint32, burst uint16) ledgerv4.SQLiteDirectIssueConfig {
	c := f.h.Config
	return ledgerv4.SQLiteDirectIssueConfig{Policy: protocolv4.DirectIssuePolicyConfig{Trust: c.Trust[0], Clock: c.Clock, Issuer: c.IssuerKeyID, Audience: c.Audience, CryptoProfile: c.CryptoProfile, PolicyID: c.RevocationPolicyID, PolicyRevision: c.RevocationPolicyRevision}, Host: f.host, MaxOutstanding: outstanding, StateBytes: 4096, RequestsPerMinute: burst, Burst: burst, WorkMS: 2000, RuntimeBytes: 8192}
}

func (f *directSQLiteFixture) authority(s *ledgerv4.SQLiteStore, c ledgerv4.SQLiteDirectIssueConfig) *ledgerv4.SQLiteDirectIssueAuthority {
	f.t.Helper()
	charge, err := ledgerv4.SQLiteDirectIssueCharge(c)
	if err != nil {
		f.t.Fatal(err)
	}
	a, err := ledgerv4.NewSQLiteDirectIssueAuthority(context.Background(), s, c, f.h.Reserve(charge), f.h.Environment)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		a.Close()
		if err := a.WaitCleanup(context.Background()); err != nil {
			f.t.Error(err)
		}
	})
	return a
}

func (f *directSQLiteFixture) issuer(a *ledgerv4.SQLiteDirectIssueAuthority) *protocolv4.DirectIssuer {
	f.t.Helper()
	c := f.h.Config
	c.Authority = a
	charge, err := protocolv4.DirectIssuerCharge(c)
	if err != nil {
		f.t.Fatal(err)
	}
	s, err := protocolv4.NewDirectIssuer(c, f.h.Reserve(charge), f.h.Environment)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		s.Close()
		if err := s.WaitCleanup(context.Background()); err != nil {
			f.t.Error(err)
		}
	})
	return s
}

func directSQLiteRequest(id byte) protocolv4.DirectIssueRequest {
	return protocolv4.DirectIssueRequest{RequestID: [32]byte{id}, Authentication: []byte("authenticated host request")}
}

func TestSQLiteDirectIssuerRealSigningSharedQuotaAndRestart(t *testing.T) {
	f := newDirectSQLiteFixture(t)
	store := f.open(true)
	c := f.config(2, 2)
	a, b := f.authority(store, c), f.authority(store, c)
	first, second := f.issuer(a), f.issuer(b)
	for i, issuer := range []*protocolv4.DirectIssuer{first, second} {
		out := make([]byte, 65536)
		n, err := issuer.IssueArtifactBytes(context.Background(), directSQLiteRequest(byte(i+1)), out)
		if err != nil || n == 0 {
			t.Fatal("real issuance failed", n, err)
		}
		clear(out)
	}
	status, err := a.Status(context.Background())
	if err != nil || status.Outstanding != 2 || status.ReservedStateBytes <= 2*92 {
		t.Fatal("lost durable obligations/evidence", status, err)
	}
	if n, err := first.IssueArtifactBytes(context.Background(), directSQLiteRequest(3), make([]byte, 65536)); err == nil || n != 0 {
		t.Fatal("instances duplicated their shared quota")
	}
	first.Close()
	second.Close()
	a.Close()
	b.Close()
	closeDirectSQLite(t, store)
	reopened := f.open(false)
	restored := f.authority(reopened, c)
	status, err = restored.Status(context.Background())
	if err != nil || status.Outstanding != 2 {
		t.Fatal("restart reset outstanding", status, err)
	}
	if _, err := restored.BeginDirectIssue(context.Background(), directSQLiteRequest(1), f.h.Facts); err == nil {
		t.Fatal("restart recovered a request's signing right")
	}
	changed := c
	changed.MaxOutstanding = 3
	charge, _ := ledgerv4.SQLiteDirectIssueCharge(changed)
	if other, err := ledgerv4.NewSQLiteDirectIssueAuthority(context.Background(), reopened, changed, f.h.Reserve(charge), f.h.Environment); err == nil || other != nil {
		t.Fatal("reconfiguration expanded persisted quota")
	}
}

func TestSQLiteDirectIssuerUncommittedObligationAndRateSurviveRestart(t *testing.T) {
	f := newDirectSQLiteFixture(t)
	store := f.open(true)
	c := f.config(3, 1)
	a := f.authority(store, c)
	request := directSQLiteRequest(4)
	permit, err := a.BeginDirectIssue(context.Background(), request, f.h.Facts)
	if err != nil {
		t.Fatal(err)
	}
	permit.Close()
	if err := permit.Check(context.Background()); !errors.Is(err, ledgerv4.ErrOwner) {
		t.Fatal("closed original permit remained live", err)
	}
	status, err := a.Status(context.Background())
	if err != nil || status.Outstanding != 1 {
		t.Fatal("Close returned durable issuance responsibility", status, err)
	}
	a.Close()
	closeDirectSQLite(t, store)
	a = f.authority(f.open(false), c)
	fresh := f.h.Facts
	fresh.LeaseID[0] ^= 0x80
	if _, err := a.BeginDirectIssue(context.Background(), directSQLiteRequest(5), fresh); !errors.Is(err, ledgerv4.ErrCapacity) {
		t.Fatal("restart restored burst tokens", err)
	}
	status, err = a.Status(context.Background())
	if err != nil || status.Outstanding != 1 {
		t.Fatal("failed request changed obligations", status, err)
	}
}

func TestSQLiteDirectIssuerRejectsMissingAuthenticationAndScope(t *testing.T) {
	f := newDirectSQLiteFixture(t)
	a := f.authority(f.open(true), f.config(3, 3))
	for _, attack := range []string{"authentication", "identity", "namespace", "policy", "cohort"} {
		request := directSQLiteRequest(8)
		facts := f.h.Facts
		switch attack {
		case "authentication":
			request.Authentication = []byte("untrusted request claim")
		case "identity":
			facts.ClientIdentity = facts.ServerIdentity
		case "namespace":
			facts.Namespaces[0].RoleMask = 1
		case "policy":
			facts.RevocationPolicyRevision++
		case "cohort":
			facts.Scope.Cohort++
		}
		if p, err := a.BeginDirectIssue(context.Background(), request, facts); err == nil || p != nil {
			t.Fatal("untrusted issuance admitted", attack)
		}
	}
	status, err := a.Status(context.Background())
	if err != nil || status.Outstanding != 0 {
		t.Fatal("refusal wrote an obligation", status, err)
	}
}
