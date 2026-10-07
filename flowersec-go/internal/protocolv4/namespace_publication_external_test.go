package protocolv4_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/floegence/flowersec/flowersec-go/v6/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type publicationHost struct {
	identity ledgerv4.SQLiteIdentity
	scope    protocolv4.NamespacePublicationScope
	denied   atomic.Bool
	client   [32]byte
}

func (h *publicationHost) Check(i ledgerv4.SQLiteIdentity, _ uint64, _ bool) error {
	if i != h.identity {
		return ledgerv4.ErrFenced
	}
	return nil
}
func (h *publicationHost) CheckPublicationMutation(s protocolv4.NamespacePublicationScope) error {
	if s != h.scope {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (h *publicationHost) CheckPublicationRead(s protocolv4.NamespacePublicationScope, auth []byte) error {
	if s != h.scope || h.denied.Load() || !(bytes.Equal(auth, []byte("namespace-reader")) || h.client != ([32]byte{}) && bytes.Equal(auth, h.client[:])) {
		return ledgerv4.ErrDenied
	}
	return nil
}

type publicationSigner struct {
	base  protocolv4.MapSigner
	calls atomic.Int32
	hook  func()
}

func (s *publicationSigner) PublicKey() []byte { return s.base.PublicKey() }
func (s *publicationSigner) Sign(input []byte) ([]byte, error) {
	s.calls.Add(1)
	if s.hook != nil {
		s.hook()
	}
	return s.base.Sign(input)
}

type publicationFixture struct {
	t         *testing.T
	h         *protocolv4.NamespacePublicationTestHarness
	host      *publicationHost
	limits    ledgerv4.SQLiteLimits
	config    controlplane.SQLitePublicationConfig
	backing   *ledgerv4.SQLiteBacking
	path      string
	store     *controlplane.SQLitePublicationStore
	stores    []*controlplane.SQLitePublicationStore
	publisher *controlplane.NamespacePublisher
	signer    *publicationSigner
}

func newPublicationFixture(t *testing.T, slots uint32) *publicationFixture {
	t.Helper()
	h := protocolv4.NewNamespacePublicationTestHarness(t)
	f := &publicationFixture{t: t, h: h, host: &publicationHost{identity: ledgerv4.SQLiteIdentity{Authority: "revocation-publication", StoreID: [32]byte{15}, Generation: 1}, scope: h.Scope}, limits: ledgerv4.SQLiteLimits{MaxPages: 256, MaxRecords: 64, MaxRecordBytes: 65536, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}, signer: &publicationSigner{base: h.Signer}}
	f.config = controlplane.SQLitePublicationConfig{Scope: h.Scope, Clock: h.Clock, Trust: h.Trust, Access: f.host, HistorySlots: slots, MaxAuthenticationBytes: 64}
	path := filepath.Join(t.TempDir(), "publication.db")
	f.path = path
	cost, err := ledgerv4.SQLiteBackingCharge(f.limits)
	if err != nil {
		t.Fatal(err)
	}
	f.backing, err = ledgerv4.NewSQLiteBacking(path, f.limits, h.Reserve(cost), h.Environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.publisher != nil {
			f.publisher.Close()
			if err := f.publisher.WaitCleanup(context.Background()); err != nil {
				t.Error(err)
			}
		}
		for _, s := range f.stores {
			f.closeStore(s)
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
	f.open(true)
	if _, err = f.store.ReplaceState(context.Background(), 0, h.State); err != nil {
		t.Fatal("initial authority state", err)
	}
	f.startPublisher()
	return f
}
func (f *publicationFixture) open(create bool) {
	f.t.Helper()
	a, b, c, err := controlplane.SQLitePublicationStoreCharges(f.limits, f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	if create {
		f.store, err = controlplane.CreateSQLitePublicationStore(context.Background(), f.backing, f.host.identity, f.host, f.config, f.h.Reserve(a), f.h.Reserve(b), f.h.Reserve(c), f.h.Environment)
	} else {
		f.store, err = controlplane.OpenSQLitePublicationStore(context.Background(), f.backing, f.host.identity, f.host, f.config, f.h.Reserve(a), f.h.Reserve(b), f.h.Reserve(c), f.h.Environment)
	}
	if err != nil {
		f.t.Fatal("open publication store", err)
	}
	f.stores = append(f.stores, f.store)
}
func (f *publicationFixture) closeStore(s *controlplane.SQLitePublicationStore) {
	f.t.Helper()
	s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.WaitCleanup(ctx); err != nil {
		f.t.Error(err)
	}
	if err := s.Retire(); err != nil {
		f.t.Error(err)
	}
}
func (f *publicationFixture) startPublisher() {
	f.t.Helper()
	c := controlplane.NamespacePublisherConfig{Clock: f.h.Clock, Trust: f.h.Trust, Store: f.store, Signer: f.signer, SignerID: f.h.SignerID, Generation: f.h.Scope.Generation, WorkMS: 2000, MinimumValidityMS: 10, RuntimeBytes: 65536}
	a, b, err := controlplane.NamespacePublisherCharges(c)
	if err != nil {
		f.t.Fatal(err)
	}
	f.publisher, err = controlplane.NewNamespacePublisher(c, f.h.Reserve(a), f.h.Reserve(b), f.h.Environment)
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *publicationFixture) read(digest [32]byte) (controlplane.NamespacePublicationVersion, []byte, []byte, error) {
	s, h := make([]byte, 4096), make([]byte, 1024)
	v, n, m, err := f.store.ReadPublished(context.Background(), []byte("namespace-reader"), digest, s, h)
	return v, s[:n], h[:m], err
}

func TestNamespacePublicConstructorsRequireCompleteWrapperCharge(t *testing.T) {
	f := newPublicationFixture(t, 4)
	short := func(cost resourcev4.Vector) resourcev4.Reference {
		cost[resourcev4.SDKBytes]--
		return f.h.Reserve(cost)
	}
	c := controlplane.NamespacePublisherConfig{Clock: f.h.Clock, Trust: f.h.Trust, Store: f.store, Signer: f.signer, SignerID: f.h.SignerID, Generation: f.h.Scope.Generation, WorkMS: 2000, MinimumValidityMS: 10, RuntimeBytes: 65536}
	a, b, err := controlplane.NamespacePublisherCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	owner, state := short(a), f.h.Reserve(b)
	if publisher, err := controlplane.NewNamespacePublisher(c, owner, state, f.h.Environment); err != controlplane.PublicationFailure("capacity_exhausted") || publisher != nil {
		if publisher != nil {
			publisher.Close()
			if err := publisher.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		t.Error("publisher accepted an incomplete wrapper charge", err)
	}
	if owner.Check() != nil || state.Check() != nil {
		t.Error("publisher refusal consumed caller ownership")
	}
	owner.Release()
	state.Release()
	_, client, _, _ := issuerHTTPCertificates(t)
	httpConfig := controlplane.NamespaceHTTPSConfig{Clock: f.h.Clock, Trust: f.h.Trust, Scope: f.h.Scope, BootstrapSigner: f.h.RootSigner, ClientCertificateDER: client.Certificate[0], RequestsPerMinute: 60, Burst: 20, WorkMS: 2000, BootstrapValidityMS: 1000, RuntimeBytes: 65536}
	a, err = controlplane.NamespaceHTTPSServiceCharge(httpConfig)
	if err != nil {
		t.Fatal(err)
	}
	owner = short(a)
	if service, err := controlplane.NewNamespaceHTTPSService(f.store, httpConfig, owner, f.h.Environment); err != controlplane.PublicationFailure("capacity_exhausted") || service != nil {
		if service != nil {
			service.Close()
			if err := service.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		t.Error("HTTPS service accepted an incomplete wrapper charge", err)
	}
	if owner.Check() != nil {
		t.Error("HTTPS refusal consumed caller ownership")
	}
	owner.Release()
	f.publisher.Close()
	if err := f.publisher.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.closeStore(f.store)
	for _, create := range []bool{false, true} {
		t.Run(map[bool]string{false: "open", true: "create"}[create], func(t *testing.T) {
			backing := f.backing
			if create {
				cost, err := ledgerv4.SQLiteBackingCharge(f.limits)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "new-publication.db")
				backing, err = ledgerv4.NewSQLiteBacking(path, f.limits, f.h.Reserve(cost), f.h.Environment)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					backing.Close()
					for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
						if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
							t.Error(err)
						}
					}
					if err := backing.ReleaseRemoved(); err != nil {
						t.Error(err)
					}
				}()
			}
			a, b, c, err := controlplane.SQLitePublicationStoreCharges(f.limits, f.config)
			if err != nil {
				t.Fatal(err)
			}
			owner, first, second := short(a), f.h.Reserve(b), f.h.Reserve(c)
			defer owner.Release()
			defer first.Release()
			defer second.Release()
			var store *controlplane.SQLitePublicationStore
			if create {
				store, err = controlplane.CreateSQLitePublicationStore(context.Background(), backing, f.host.identity, f.host, f.config, owner, first, second, f.h.Environment)
			} else {
				store, err = controlplane.OpenSQLitePublicationStore(context.Background(), backing, f.host.identity, f.host, f.config, owner, first, second, f.h.Environment)
			}
			if store != nil {
				f.closeStore(store)
			}
			if err != controlplane.PublicationFailure("capacity_exhausted") || store != nil {
				t.Error("publication store accepted an incomplete wrapper charge", err)
			}
			if owner.Check() != nil || first.Check() != nil || second.Check() != nil {
				t.Error("store refusal consumed caller ownership")
			}
		})
	}
}

func TestNamespacePublicationSnapshotDuringMutationAndRestart(t *testing.T) {
	f := newPublicationFixture(t, 4)
	f.signer.hook = func() {
		if _, err := f.store.ReplaceState(context.Background(), 1, f.h.Changed); err != nil {
			t.Fatal("ordinary update blocked by signer", err)
		}
		f.h.Advance(100)
		if _, _, _, err := f.read([32]byte{}); err == nil {
			t.Fatal("uncommitted signature became readable")
		}
	}
	first, err := f.publisher.Publish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || first.Snapshot != 1 || first.ThisUpdateMS != 1100 || f.signer.calls.Load() != 1 {
		t.Fatal("snapshot resampled or signing retried", first)
	}
	v, state, _, err := f.read([32]byte{})
	if err != nil || v != first || !bytes.Equal(state, f.h.State) {
		t.Fatal("fixed snapshot changed", err)
	}
	f.signer.hook = nil
	second, err := f.publisher.Publish(context.Background())
	if err != nil || second.Sequence != 2 || second.Snapshot != 2 || second.ThisUpdateMS != 1200 {
		t.Fatal("next snapshot not current", second, err)
	}
	_, state, _, err = f.read(first.StateDigest)
	if err != nil || !bytes.Equal(state, f.h.State) {
		t.Fatal("unexpired State evicted", err)
	}
	if _, err = f.store.ReplaceState(context.Background(), 2, f.h.State); err == nil {
		t.Fatal("revocation removal accepted without floor")
	}
	f.publisher.Close()
	if err = f.publisher.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.closeStore(f.store)
	f.open(false)
	f.startPublisher()
	third, err := f.publisher.Publish(context.Background())
	if err != nil || third.Sequence != 3 || third.Snapshot != 2 {
		t.Fatal("restart lost high-water mark", third, err)
	}
	f.host.denied.Store(true)
	if _, _, _, err = f.read(first.StateDigest); err == nil {
		t.Fatal("cached digest bypassed full-namespace ACL")
	}
}

func TestNamespacePublicationCurrentRecordsCheckedBeforeFencing(t *testing.T) {
	for _, mutation := range []string{"historical", "current-digest", "current-state", "retained-state", "head", "sequence", "head-window", "snapshot"} {
		t.Run(mutation, func(t *testing.T) {
			f := newPublicationFixture(t, 4)
			first, err := f.publisher.Publish(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.ReplaceState(context.Background(), 1, f.h.Changed); err != nil {
				t.Fatal(err)
			}
			if _, err = f.publisher.Publish(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.publisher.Close()
			if err = f.publisher.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.closeStore(f.store)
			db, err := sql.Open("sqlite", f.path)
			if err != nil {
				t.Fatal(err)
			}
			var oldEpoch []byte
			if err = db.QueryRow("SELECT epoch FROM manifest").Scan(&oldEpoch); err != nil {
				t.Fatal(err)
			}
			var statement string
			switch mutation {
			case "current-digest":
				statement = "UPDATE current_state SET digest=zeroblob(32)"
			case "current-state":
				statement = "UPDATE chunks SET data=zeroblob(length(data)) WHERE slot=0"
			case "retained-state":
				statement = "UPDATE chunks SET data=zeroblob(length(data)) WHERE slot=(SELECT slot FROM publications ORDER BY sequence LIMIT 1)"
			case "head":
				statement = "UPDATE publications SET head=zeroblob(length(head)) WHERE slot=(SELECT slot FROM publications ORDER BY sequence LIMIT 1)"
			case "sequence":
				statement = "UPDATE publications SET sequence=x'0000000000000003' WHERE slot=(SELECT slot FROM publications ORDER BY sequence LIMIT 1)"
			case "head-window":
				statement = "UPDATE publications SET next_update=x'000000000000ffff' WHERE slot=(SELECT slot FROM publications ORDER BY sequence LIMIT 1)"
			case "snapshot":
				statement = "UPDATE publications SET snapshot=x'0000000000000002' WHERE slot=(SELECT slot FROM publications ORDER BY sequence LIMIT 1)"
			}
			if statement != "" {
				if _, err = db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "historical" {
				f.h.RejectSigner()
				f.h.Advance(first.NextUpdateMS - first.ThisUpdateMS + 1)
			}
			a, b, c, err := controlplane.SQLitePublicationStoreCharges(f.limits, f.config)
			if err != nil {
				t.Fatal(err)
			}
			store, err := controlplane.OpenSQLitePublicationStore(context.Background(), f.backing, f.host.identity, f.host, f.config, f.h.Reserve(a), f.h.Reserve(b), f.h.Reserve(c), f.h.Environment)
			if mutation == "historical" {
				if err != nil {
					t.Fatal("historical publication was refused", err)
				}
				f.stores = append(f.stores, store)
				f.closeStore(store)
				db, err = sql.Open("sqlite", f.path)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				var epoch []byte
				if err = db.QueryRow("SELECT epoch FROM manifest").Scan(&epoch); err != nil {
					t.Fatal(err)
				}
				if binary.BigEndian.Uint64(epoch) != binary.BigEndian.Uint64(oldEpoch)+1 {
					t.Fatal("historical open did not fence exactly once")
				}
				var count int
				if err = db.QueryRow("SELECT count(*) FROM publications").Scan(&count); err != nil || count != 2 {
					t.Fatal("historical rows were lost", count, err)
				}
				return
			}
			if store != nil {
				f.stores = append(f.stores, store)
				t.Fatal("damaged publication restored an owner")
			}
			var format *ledgerv4.StorageFormatError
			if !errors.As(err, &format) || format.Projection().Reason != ledgerv4.StorageFormatState || format.Projection().ObservedRevision != (ledgerv4.StorageRevision{Known: true, Value: 1}) {
				t.Fatal("missing finite format refusal", err)
			}
			after, err := os.ReadFile(f.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal rewrote publication history", err)
			}
		})
	}
}

func TestNamespacePublicationFullHistoryDoesNotBlockRevocation(t *testing.T) {
	f := newPublicationFixture(t, 2)
	for range 2 {
		if _, err := f.publisher.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.ReplaceState(context.Background(), 1, f.h.Changed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.publisher.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A new complete content revision needs a third retained position.
	changed := bytes.Clone(f.h.Changed)
	// The fixture changes only the final positive impact value 9000 -> 9001;
	// this is legal monotonic evidence for the same revoked lease.
	index := bytes.Index(changed, []byte{0x19, 0x23, 0x28})
	if index < 0 {
		t.Fatal("fixture impact not found")
	}
	changed[index+2]++
	if _, err := f.store.ReplaceState(context.Background(), 2, changed); err != nil {
		t.Fatal("full distribution history blocked authoritative revocation", err)
	}
	if _, err := f.publisher.Publish(context.Background()); err != controlplane.PublicationFailure("capacity_exhausted") {
		t.Fatal("unexpired history silently evicted", err)
	}
	if f.signer.calls.Load() != 3 {
		t.Fatal("signed without publication capacity")
	}
}

func TestNamespacePublicationEmergencySignerAndCloseFence(t *testing.T) {
	t.Run("emergency", func(t *testing.T) {
		f := newPublicationFixture(t, 2)
		f.signer.hook = f.h.RejectSigner
		if _, err := f.publisher.Publish(context.Background()); err == nil {
			t.Fatal("emergency rejection failed to fence private signature")
		}
		if _, _, _, err := f.read([32]byte{}); err == nil {
			t.Fatal("rejected candidate distributed")
		}
	})
	t.Run("close", func(t *testing.T) {
		f := newPublicationFixture(t, 2)
		entered, release := make(chan struct{}), make(chan struct{})
		releaseSigner := sync.OnceFunc(func() { close(release) })
		defer releaseSigner()
		f.signer.hook = func() { close(entered); <-release }
		finished := make(chan error, 1)
		go func() { _, err := f.publisher.Publish(context.Background()); finished <- err }()
		<-entered
		f.publisher.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		if err := f.publisher.WaitCleanup(ctx); err != controlplane.PublicationFailure("expired") {
			t.Fatal("stalled signer backing released", err)
		}
		cancel()
		releaseSigner()
		if err := <-finished; err == nil {
			t.Fatal("closed job committed")
		}
		if err := f.publisher.WaitCleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := f.read([32]byte{}); err == nil {
			t.Fatal("late signature distributed")
		}
	})
}

func TestNamespacePublicationHTTPSOriginalConsumerProvider(t *testing.T) {
	f := newPublicationFixture(t, 4)
	first, err := f.publisher.Publish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	serverCert, clientCert, strangerCert, roots := issuerHTTPCertificates(t)
	f.host.client = sha256.Sum256(clientCert.Certificate[0])
	c := controlplane.NamespaceHTTPSConfig{Clock: f.h.Clock, Trust: f.h.Trust, Scope: f.h.Scope, BootstrapSigner: f.h.RootSigner, ClientCertificateDER: clientCert.Certificate[0], RequestsPerMinute: 60, Burst: 20, WorkMS: 2000, BootstrapValidityMS: 1000, RuntimeBytes: 65536}
	cost, err := controlplane.NamespaceHTTPSServiceCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	service, err := controlplane.NewNamespaceHTTPSService(f.store, c, f.h.Reserve(cost), f.h.Environment)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(service)
	server.TLS, err = controlv4.OperationsTLSConfig(serverCert, roots)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS.Time = func() time.Time { return time.UnixMilli(1100) }
	server.StartTLS()
	defer server.Close()
	defer func() {
		service.Close()
		if err := service.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	config := controlv4.HTTPSBootstrapConfig{BaseURL: server.URL, RemoteAddress: netip.MustParseAddrPort(server.Listener.Addr().String()), TLS: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13, Time: server.TLS.Time}, HeaderBytes: 4096, Timeout: 2 * time.Second, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20}
	charge, err := controlv4.HTTPSBootstrapCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	borrow, err := f.h.Environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := controlv4.NewHTTPSBootstrapProvider(config, f.h.Reserve(charge), borrow)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		provider.Close()
		if err := provider.Retire(); err != nil {
			t.Error(err)
		}
	}()
	request := protocolv4.NamespaceRefreshRequest{Tenant: f.h.Scope.Tenant, Authority: f.h.Scope.Authority}
	head := make([]byte, 795)
	n, err := provider.Head(context.Background(), request, head)
	if err != nil || n == 0 {
		t.Fatal("actual HTTPS Head", err)
	}
	_, expectedState, expectedHead, err := f.read([32]byte{})
	if err != nil || !bytes.Equal(head[:n], expectedHead) {
		t.Fatal("Head response changed", err)
	}
	state := make([]byte, len(expectedState))
	if n, err = provider.Fetch(context.Background(), protocolv4.NamespaceContent{Digest: first.StateDigest, EncodedBytes: uint64(len(state))}, state); err != nil || n != len(state) || !bytes.Equal(state, expectedState) {
		t.Fatal("actual HTTPS complete State", err)
	}
	trust := make([]byte, 262144)
	if n, err = provider.Trust(context.Background(), request, trust); err != nil || n == 0 {
		t.Fatal("actual HTTPS Trust", err)
	}
	bootstrap := make([]byte, 270336)
	nonce := [32]byte{73}
	n, err = provider.Query(context.Background(), protocolv4.NamespaceBootstrapRequest{Tenant: request.Tenant, Authority: request.Authority, Nonce: nonce}, bootstrap)
	if err != nil {
		t.Fatal("actual HTTPS bootstrap", err)
	}
	codec, err := protocolv4.NewSignedMapCodec("TrustBootstrapResponse", 270336, 270336)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.Verify(bootstrap[:n], [32]byte(f.h.RootSigner.PublicKey()), protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Release()
	gotNonce, _ := signed.Field("request_nonce").ByteString()
	gotHead, _ := signed.Field("freshness_head").ByteString()
	if !bytes.Equal(gotNonce, nonce[:]) || !bytes.Equal(gotHead, expectedHead) || f.signer.calls.Load() != 1 {
		t.Fatal("read signed a new Head or changed nonce binding")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{strangerCert}, MinVersion: tls.VersionTLS13, Time: server.TLS.Time}}
	defer transport.CloseIdleConnections()
	query := url.Values{"digest": {hex.EncodeToString(first.StateDigest[:])}, "encoded_bytes": {strconv.Itoa(len(state))}}
	response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(server.URL + "/state?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("same CA and digest bypassed client registration", response.StatusCode)
	}
	f.host.denied.Store(true)
	if _, err = provider.Head(context.Background(), request, head); err == nil {
		t.Fatal("revoked visibility served cached Head")
	}
}
