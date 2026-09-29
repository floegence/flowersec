package controlplane

import (
	"context"
	"errors"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type V4DirectIssueRequest = protocolv4.DirectIssueRequest
type V4DirectIssueFacts = protocolv4.DirectIssueFacts
type V4DirectIssueAuthority = protocolv4.DirectIssueAuthority
type V4DirectIssuePermit = protocolv4.DirectIssuePermit
type V4DirectIssuerConfig = protocolv4.DirectIssuerConfig
type V4DirectIssuePolicyConfig = protocolv4.DirectIssuePolicyConfig
type V4DirectIssuePolicyLimits = protocolv4.DirectIssuePolicyLimits
type V4SQLiteDirectIssueHost = ledgerv4.SQLiteDirectIssueHost
type V4SQLiteDirectIssueAccess = ledgerv4.SQLiteDirectIssueAccess
type V4SQLiteDirectIssueConfig = ledgerv4.SQLiteDirectIssueConfig
type V4SQLiteDirectIssueStatus = ledgerv4.SQLiteDirectIssueStatus
type V4SQLiteDirectIssuePublication = ledgerv4.SQLiteDirectIssuePublication
type V4DirectIssueObligationState = ledgerv4.DirectIssueObligationState

const (
	V4DirectIssueReserved  = ledgerv4.DirectIssueReserved
	V4DirectIssueCommitted = ledgerv4.DirectIssueCommitted
	V4DirectIssueRetired   = ledgerv4.DirectIssueRetired
)

type V4SQLiteDirectIssueAuthority = ledgerv4.SQLiteDirectIssueAuthority

func V4SQLiteDirectIssueCharge(c V4SQLiteDirectIssueConfig) (resourcev4.Vector, error) {
	charge, err := ledgerv4.SQLiteDirectIssueCharge(c)
	return charge, v4IssueFailure(err)
}

func NewV4SQLiteDirectIssueAuthority(ctx context.Context, store *ledgerv4.SQLiteStore, c V4SQLiteDirectIssueConfig, reservation, dependencies resourcev4.Reference) (*V4SQLiteDirectIssueAuthority, error) {
	a, err := ledgerv4.NewSQLiteDirectIssueAuthority(ctx, store, c, reservation, dependencies)
	return a, v4IssueFailure(err)
}

// V4IssueFailure contains only bounded public categories, never provider text,
// caller authentication, secret material, signed documents or storage details.
type V4IssueFailure string

func (e V4IssueFailure) Error() string { return string(e) }

func v4IssueFailure(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return V4IssueFailure("cancelled")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, timev4.ErrExpired):
		return V4IssueFailure("expired")
	case errors.Is(err, resourcev4.ErrCapacity):
		return V4IssueFailure("capacity_exhausted")
	case errors.Is(err, resourcev4.ErrClosed):
		return V4IssueFailure("closed")
	case errors.Is(err, resourcev4.ErrConfiguration):
		return V4IssueFailure("configuration_invalid")
	default:
		return V4IssueFailure("issuance_refused")
	}
}

// V4DirectIssuer is an embeddable reference issuer for canonical direct/local
// v4 Artifacts. Host configuration fixes verified identities and route policy;
// a separate authenticated authority must durably reserve each original lease
// obligation before signing. It does not create activation or spend material.
type V4DirectIssuer struct{ inner *protocolv4.DirectIssuer }

func V4DirectIssuerCharge(c V4DirectIssuerConfig) (resourcev4.Vector, error) {
	charge, err := protocolv4.DirectIssuerCharge(c)
	if err == nil {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(V4DirectIssuer{}))})
	}
	return charge, v4IssueFailure(err)
}

func NewV4DirectIssuer(c V4DirectIssuerConfig, reservation, dependencies resourcev4.Reference) (*V4DirectIssuer, error) {
	charge, err := V4DirectIssuerCharge(c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, v4IssueFailure(err)
	}
	defer owned.Release()
	issuer, err := protocolv4.NewDirectIssuer(c, owned, dependencies)
	if err != nil {
		return nil, v4IssueFailure(err)
	}
	return &V4DirectIssuer{inner: issuer}, nil
}

// IssueArtifactBytes requires a caller-reserved 65536-byte response buffer.
// Only the returned prefix is valid on success. The host delivers and erases
// these secret-bearing bytes through its independently authenticated channel.
func (s *V4DirectIssuer) IssueArtifactBytes(ctx context.Context, request V4DirectIssueRequest, dst []byte) (int, error) {
	if s == nil || s.inner == nil {
		return 0, V4IssueFailure("closed")
	}
	n, err := s.inner.IssueArtifactBytes(ctx, request, dst)
	return n, v4IssueFailure(err)
}

func (s *V4DirectIssuer) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}

func (s *V4DirectIssuer) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return V4IssueFailure("closed")
	}
	return v4IssueFailure(s.inner.WaitCleanup(ctx))
}

func (*V4DirectIssuer) String() string   { return "V4DirectIssuer(<redacted>)" }
func (*V4DirectIssuer) GoString() string { return "V4DirectIssuer(<redacted>)" }
