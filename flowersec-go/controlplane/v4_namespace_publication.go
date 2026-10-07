package controlplane

import (
	"context"
	"errors"
	"net/http"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type NamespacePublicationScope = protocolv4.NamespacePublicationScope
type NamespacePublicationVersion = protocolv4.NamespacePublicationVersion
type PublicationAuthority = ledgerv4.PublicationAuthority
type SQLitePublicationConfig = ledgerv4.SQLitePublicationConfig
type NamespaceHTTPSConfig = controlv4.NamespaceHTTPSConfig
type NamespaceHTTPSService struct {
	inner *controlv4.NamespaceHTTPSService
}

func NamespaceHTTPSServiceCharge(c NamespaceHTTPSConfig) (resourcev4.Vector, error) {
	v, err := controlv4.NamespaceHTTPSServiceCharge(c)
	if err == nil {
		v, err = v.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespaceHTTPSService{}))})
	}
	return v, v4PublicationFailure(err)
}
func NewNamespaceHTTPSService(store *SQLitePublicationStore, c NamespaceHTTPSConfig, reservation, dependencies resourcev4.Reference) (*NamespaceHTTPSService, error) {
	if store == nil || store.inner == nil {
		return nil, PublicationFailure("configuration_invalid")
	}
	charge, err := NamespaceHTTPSServiceCharge(c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, v4PublicationFailure(err)
	}
	defer owned.Release()
	s, err := controlv4.NewNamespaceHTTPSService(store.inner, c, owned, dependencies)
	if err != nil {
		return nil, v4PublicationFailure(err)
	}
	return &NamespaceHTTPSService{s}, nil
}
func (s *NamespaceHTTPSService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.inner == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.inner.ServeHTTP(w, r)
}
func (s *NamespaceHTTPSService) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
func (s *NamespaceHTTPSService) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return PublicationFailure("closed")
	}
	return v4PublicationFailure(s.inner.WaitCleanup(ctx))
}

// The public store exposes authenticated full-State replacement and reads.
// Private signing claims, fencing continuations and uncommitted bytes never
// escape this assembly. SQLite continuity remains an independent host duty.
type SQLitePublicationStore struct {
	inner *ledgerv4.SQLitePublicationStore
}
type NamespacePublisher struct {
	inner *protocolv4.NamespacePublisher
}

type NamespacePublisherConfig struct {
	Clock                                   *timev4.Clock
	Trust                                   *protocolv4.NamespaceTrustStore
	Store                                   *SQLitePublicationStore
	Signer                                  protocolv4.MapSigner
	SignerID                                [16]byte
	Generation                              uint64
	WorkMS, MinimumValidityMS, RuntimeBytes uint64
}

type PublicationFailure string

func (e PublicationFailure) Error() string { return string(e) }
func v4PublicationFailure(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return PublicationFailure("cancelled")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, timev4.ErrExpired):
		return PublicationFailure("expired")
	case errors.Is(err, ledgerv4.ErrUnknown):
		return PublicationFailure("publication_unknown")
	case errors.Is(err, ledgerv4.ErrConflict), errors.Is(err, ledgerv4.ErrFenced):
		return PublicationFailure("publication_conflict")
	case errors.Is(err, resourcev4.ErrCapacity), errors.Is(err, ledgerv4.ErrCapacity):
		return PublicationFailure("capacity_exhausted")
	case errors.Is(err, resourcev4.ErrClosed), errors.Is(err, ledgerv4.ErrOwner):
		return PublicationFailure("closed")
	case errors.Is(err, ledgerv4.ErrMissingPublication):
		return PublicationFailure("publication_unavailable")
	case errors.Is(err, resourcev4.ErrConfiguration), errors.Is(err, ledgerv4.ErrConfiguration):
		return PublicationFailure("configuration_invalid")
	case errors.Is(err, ledgerv4.ErrStorageFormat):
		var format *ledgerv4.StorageFormatError
		if errors.As(err, &format) && format != nil {
			return format
		}
		return ledgerv4.ErrStorageFormat
	default:
		return PublicationFailure("publication_refused")
	}
}

func SQLitePublicationStoreCharges(l ledgerv4.SQLiteLimits, c SQLitePublicationConfig) (owner, first, second resourcev4.Vector, err error) {
	owner, first, second, err = ledgerv4.SQLitePublicationStoreCharges(l, c)
	if err == nil {
		owner, err = owner.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLitePublicationStore{}))})
	}
	err = v4PublicationFailure(err)
	return
}

func CreateSQLitePublicationStore(ctx context.Context, b *ledgerv4.SQLiteBacking, i ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, c SQLitePublicationConfig, owner, first, second, dependencies resourcev4.Reference) (*SQLitePublicationStore, error) {
	return openSQLitePublicationStore(ctx, b, i, continuity, c, owner, first, second, dependencies, true)
}
func OpenSQLitePublicationStore(ctx context.Context, b *ledgerv4.SQLiteBacking, i ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, c SQLitePublicationConfig, owner, first, second, dependencies resourcev4.Reference) (*SQLitePublicationStore, error) {
	return openSQLitePublicationStore(ctx, b, i, continuity, c, owner, first, second, dependencies, false)
}
func openSQLitePublicationStore(ctx context.Context, b *ledgerv4.SQLiteBacking, i ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, c SQLitePublicationConfig, owner, first, second, dependencies resourcev4.Reference, create bool) (*SQLitePublicationStore, error) {
	charge, _, _, err := SQLitePublicationStoreCharges(b.Limits(), c)
	if err != nil {
		return nil, err
	}
	owned, err := owner.Take(charge)
	if err != nil {
		return nil, v4PublicationFailure(err)
	}
	defer owned.Release()
	var p *ledgerv4.SQLitePublicationStore
	if create {
		p, err = ledgerv4.CreateSQLitePublicationStore(ctx, b, i, continuity, c, owned, first, second, dependencies)
	} else {
		p, err = ledgerv4.OpenSQLitePublicationStore(ctx, b, i, continuity, c, owned, first, second, dependencies)
	}
	if p == nil {
		return nil, v4PublicationFailure(err)
	}
	return &SQLitePublicationStore{p}, v4PublicationFailure(err)
}
func (p *SQLitePublicationStore) ReplaceState(ctx context.Context, expected uint64, wire []byte) (uint64, error) {
	if p == nil || p.inner == nil {
		return 0, PublicationFailure("closed")
	}
	v, err := p.inner.ReplaceState(ctx, expected, wire)
	return v, v4PublicationFailure(err)
}
func (p *SQLitePublicationStore) ReadPublished(ctx context.Context, authentication []byte, digest [32]byte, state, head []byte) (NamespacePublicationVersion, int, int, error) {
	if p == nil || p.inner == nil {
		return NamespacePublicationVersion{}, 0, 0, PublicationFailure("closed")
	}
	v, n, h, err := p.inner.ReadPublished(ctx, authentication, digest, state, head)
	return v, n, h, v4PublicationFailure(err)
}
func (p *SQLitePublicationStore) Close() {
	if p != nil && p.inner != nil {
		p.inner.Close()
	}
}
func (p *SQLitePublicationStore) WaitCleanup(ctx context.Context) error {
	if p == nil || p.inner == nil {
		return PublicationFailure("closed")
	}
	return v4PublicationFailure(p.inner.WaitCleanup(ctx))
}
func (p *SQLitePublicationStore) Retire() error {
	if p == nil || p.inner == nil {
		return PublicationFailure("closed")
	}
	return v4PublicationFailure(p.inner.Retire())
}
func (*SQLitePublicationStore) String() string   { return "SQLitePublicationStore(<redacted>)" }
func (*SQLitePublicationStore) GoString() string { return "SQLitePublicationStore(<redacted>)" }

func publicationConfig(c NamespacePublisherConfig) (protocolv4.NamespacePublisherConfig, error) {
	if c.Store == nil || c.Store.inner == nil {
		return protocolv4.NamespacePublisherConfig{}, PublicationFailure("configuration_invalid")
	}
	return protocolv4.NamespacePublisherConfig{Clock: c.Clock, Trust: c.Trust, Store: c.Store.inner, Signer: c.Signer, SignerID: c.SignerID, Generation: c.Generation, WorkMS: c.WorkMS, MinimumValidityMS: c.MinimumValidityMS, RuntimeBytes: c.RuntimeBytes}, nil
}
func NamespacePublisherCharges(c NamespacePublisherConfig) (owner, state resourcev4.Vector, err error) {
	internal, err := publicationConfig(c)
	if err != nil {
		return owner, state, err
	}
	owner, state, err = protocolv4.NamespacePublisherCharges(internal)
	if err == nil {
		owner, err = owner.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespacePublisher{}))})
	}
	err = v4PublicationFailure(err)
	return
}
func NewNamespacePublisher(c NamespacePublisherConfig, owner, state, dependencies resourcev4.Reference) (*NamespacePublisher, error) {
	internal, err := publicationConfig(c)
	if err != nil {
		return nil, err
	}
	charge, _, err := NamespacePublisherCharges(c)
	if err != nil {
		return nil, err
	}
	owned, err := owner.Take(charge)
	if err != nil {
		return nil, v4PublicationFailure(err)
	}
	defer owned.Release()
	p, err := protocolv4.NewNamespacePublisher(internal, owned, state, dependencies)
	if err != nil {
		return nil, v4PublicationFailure(err)
	}
	return &NamespacePublisher{p}, nil
}
func (p *NamespacePublisher) Publish(ctx context.Context) (NamespacePublicationVersion, error) {
	if p == nil || p.inner == nil {
		return NamespacePublicationVersion{}, PublicationFailure("closed")
	}
	v, err := p.inner.Publish(ctx)
	return v, v4PublicationFailure(err)
}
func (p *NamespacePublisher) Close() {
	if p != nil && p.inner != nil {
		p.inner.Close()
	}
}
func (p *NamespacePublisher) WaitCleanup(ctx context.Context) error {
	if p == nil || p.inner == nil {
		return PublicationFailure("closed")
	}
	return v4PublicationFailure(p.inner.WaitCleanup(ctx))
}
func (*NamespacePublisher) String() string   { return "NamespacePublisher(<redacted>)" }
func (*NamespacePublisher) GoString() string { return "NamespacePublisher(<redacted>)" }
