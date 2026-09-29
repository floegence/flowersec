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

type V4NamespacePublicationScope = protocolv4.NamespacePublicationScope
type V4NamespacePublicationVersion = protocolv4.NamespacePublicationVersion
type V4PublicationAuthority = ledgerv4.PublicationAuthority
type V4SQLitePublicationConfig = ledgerv4.SQLitePublicationConfig
type V4NamespaceHTTPSConfig = controlv4.NamespaceHTTPSConfig
type V4NamespaceHTTPSService struct {
	inner *controlv4.NamespaceHTTPSService
}

func V4NamespaceHTTPSServiceCharge(c V4NamespaceHTTPSConfig) (resourcev4.Vector, error) {
	v, err := controlv4.NamespaceHTTPSServiceCharge(c)
	if err == nil {
		v, err = v.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(V4NamespaceHTTPSService{}))})
	}
	return v, v4PublicationFailure(err)
}
func NewV4NamespaceHTTPSService(store *V4SQLitePublicationStore, c V4NamespaceHTTPSConfig, reservation, dependencies resourcev4.Reference) (*V4NamespaceHTTPSService, error) {
	if store == nil || store.inner == nil {
		return nil, V4PublicationFailure("configuration_invalid")
	}
	charge, err := V4NamespaceHTTPSServiceCharge(c)
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
	return &V4NamespaceHTTPSService{s}, nil
}
func (s *V4NamespaceHTTPSService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.inner == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.inner.ServeHTTP(w, r)
}
func (s *V4NamespaceHTTPSService) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
func (s *V4NamespaceHTTPSService) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return V4PublicationFailure("closed")
	}
	return v4PublicationFailure(s.inner.WaitCleanup(ctx))
}

// The public store exposes authenticated full-State replacement and reads.
// Private signing claims, fencing continuations and uncommitted bytes never
// escape this assembly. SQLite continuity remains an independent host duty.
type V4SQLitePublicationStore struct {
	inner *ledgerv4.SQLitePublicationStore
}
type V4NamespacePublisher struct {
	inner *protocolv4.NamespacePublisher
}

type V4NamespacePublisherConfig struct {
	Clock                                   *timev4.Clock
	Trust                                   *protocolv4.NamespaceTrustStore
	Store                                   *V4SQLitePublicationStore
	Signer                                  protocolv4.MapSigner
	SignerID                                [16]byte
	Generation                              uint64
	WorkMS, MinimumValidityMS, RuntimeBytes uint64
}

type V4PublicationFailure string

func (e V4PublicationFailure) Error() string { return string(e) }
func v4PublicationFailure(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return V4PublicationFailure("cancelled")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, timev4.ErrExpired):
		return V4PublicationFailure("expired")
	case errors.Is(err, ledgerv4.ErrUnknown):
		return V4PublicationFailure("publication_unknown")
	case errors.Is(err, ledgerv4.ErrConflict), errors.Is(err, ledgerv4.ErrFenced):
		return V4PublicationFailure("publication_conflict")
	case errors.Is(err, resourcev4.ErrCapacity), errors.Is(err, ledgerv4.ErrCapacity):
		return V4PublicationFailure("capacity_exhausted")
	case errors.Is(err, resourcev4.ErrClosed), errors.Is(err, ledgerv4.ErrOwner):
		return V4PublicationFailure("closed")
	case errors.Is(err, ledgerv4.ErrMissingPublication):
		return V4PublicationFailure("publication_unavailable")
	case errors.Is(err, resourcev4.ErrConfiguration), errors.Is(err, ledgerv4.ErrConfiguration):
		return V4PublicationFailure("configuration_invalid")
	case errors.Is(err, ledgerv4.ErrStorageFormat):
		var format *ledgerv4.StorageFormatError
		if errors.As(err, &format) && format != nil {
			return format
		}
		return ledgerv4.ErrStorageFormat
	default:
		return V4PublicationFailure("publication_refused")
	}
}

func V4SQLitePublicationStoreCharges(l ledgerv4.SQLiteLimits, c V4SQLitePublicationConfig) (owner, first, second resourcev4.Vector, err error) {
	owner, first, second, err = ledgerv4.SQLitePublicationStoreCharges(l, c)
	if err == nil {
		owner, err = owner.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(V4SQLitePublicationStore{}))})
	}
	err = v4PublicationFailure(err)
	return
}

func CreateV4SQLitePublicationStore(ctx context.Context, b *ledgerv4.SQLiteBacking, i ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, c V4SQLitePublicationConfig, owner, first, second, dependencies resourcev4.Reference) (*V4SQLitePublicationStore, error) {
	return openV4SQLitePublicationStore(ctx, b, i, continuity, c, owner, first, second, dependencies, true)
}
func OpenV4SQLitePublicationStore(ctx context.Context, b *ledgerv4.SQLiteBacking, i ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, c V4SQLitePublicationConfig, owner, first, second, dependencies resourcev4.Reference) (*V4SQLitePublicationStore, error) {
	return openV4SQLitePublicationStore(ctx, b, i, continuity, c, owner, first, second, dependencies, false)
}
func openV4SQLitePublicationStore(ctx context.Context, b *ledgerv4.SQLiteBacking, i ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, c V4SQLitePublicationConfig, owner, first, second, dependencies resourcev4.Reference, create bool) (*V4SQLitePublicationStore, error) {
	charge, _, _, err := V4SQLitePublicationStoreCharges(b.Limits(), c)
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
	return &V4SQLitePublicationStore{p}, v4PublicationFailure(err)
}
func (p *V4SQLitePublicationStore) ReplaceState(ctx context.Context, expected uint64, wire []byte) (uint64, error) {
	if p == nil || p.inner == nil {
		return 0, V4PublicationFailure("closed")
	}
	v, err := p.inner.ReplaceState(ctx, expected, wire)
	return v, v4PublicationFailure(err)
}
func (p *V4SQLitePublicationStore) ReadPublished(ctx context.Context, authentication []byte, digest [32]byte, state, head []byte) (V4NamespacePublicationVersion, int, int, error) {
	if p == nil || p.inner == nil {
		return V4NamespacePublicationVersion{}, 0, 0, V4PublicationFailure("closed")
	}
	v, n, h, err := p.inner.ReadPublished(ctx, authentication, digest, state, head)
	return v, n, h, v4PublicationFailure(err)
}
func (p *V4SQLitePublicationStore) Close() {
	if p != nil && p.inner != nil {
		p.inner.Close()
	}
}
func (p *V4SQLitePublicationStore) WaitCleanup(ctx context.Context) error {
	if p == nil || p.inner == nil {
		return V4PublicationFailure("closed")
	}
	return v4PublicationFailure(p.inner.WaitCleanup(ctx))
}
func (p *V4SQLitePublicationStore) Retire() error {
	if p == nil || p.inner == nil {
		return V4PublicationFailure("closed")
	}
	return v4PublicationFailure(p.inner.Retire())
}
func (*V4SQLitePublicationStore) String() string   { return "V4SQLitePublicationStore(<redacted>)" }
func (*V4SQLitePublicationStore) GoString() string { return "V4SQLitePublicationStore(<redacted>)" }

func publicationConfig(c V4NamespacePublisherConfig) (protocolv4.NamespacePublisherConfig, error) {
	if c.Store == nil || c.Store.inner == nil {
		return protocolv4.NamespacePublisherConfig{}, V4PublicationFailure("configuration_invalid")
	}
	return protocolv4.NamespacePublisherConfig{Clock: c.Clock, Trust: c.Trust, Store: c.Store.inner, Signer: c.Signer, SignerID: c.SignerID, Generation: c.Generation, WorkMS: c.WorkMS, MinimumValidityMS: c.MinimumValidityMS, RuntimeBytes: c.RuntimeBytes}, nil
}
func V4NamespacePublisherCharges(c V4NamespacePublisherConfig) (owner, state resourcev4.Vector, err error) {
	internal, err := publicationConfig(c)
	if err != nil {
		return owner, state, err
	}
	owner, state, err = protocolv4.NamespacePublisherCharges(internal)
	if err == nil {
		owner, err = owner.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(V4NamespacePublisher{}))})
	}
	err = v4PublicationFailure(err)
	return
}
func NewV4NamespacePublisher(c V4NamespacePublisherConfig, owner, state, dependencies resourcev4.Reference) (*V4NamespacePublisher, error) {
	internal, err := publicationConfig(c)
	if err != nil {
		return nil, err
	}
	charge, _, err := V4NamespacePublisherCharges(c)
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
	return &V4NamespacePublisher{p}, nil
}
func (p *V4NamespacePublisher) Publish(ctx context.Context) (V4NamespacePublicationVersion, error) {
	if p == nil || p.inner == nil {
		return V4NamespacePublicationVersion{}, V4PublicationFailure("closed")
	}
	v, err := p.inner.Publish(ctx)
	return v, v4PublicationFailure(err)
}
func (p *V4NamespacePublisher) Close() {
	if p != nil && p.inner != nil {
		p.inner.Close()
	}
}
func (p *V4NamespacePublisher) WaitCleanup(ctx context.Context) error {
	if p == nil || p.inner == nil {
		return V4PublicationFailure("closed")
	}
	return v4PublicationFailure(p.inner.WaitCleanup(ctx))
}
func (*V4NamespacePublisher) String() string   { return "V4NamespacePublisher(<redacted>)" }
func (*V4NamespacePublisher) GoString() string { return "V4NamespacePublisher(<redacted>)" }
