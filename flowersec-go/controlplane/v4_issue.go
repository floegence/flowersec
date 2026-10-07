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

type DirectIssueRequest = protocolv4.DirectIssueRequest
type DirectIssueFacts = protocolv4.DirectIssueFacts
type DirectIssueAuthority = protocolv4.DirectIssueAuthority
type DirectIssuePermit = protocolv4.DirectIssuePermit
type DirectIssuerConfig = protocolv4.DirectIssuerConfig
type DirectIssuePolicyConfig = protocolv4.DirectIssuePolicyConfig
type DirectIssuePolicyLimits = protocolv4.DirectIssuePolicyLimits
type SQLiteDirectIssueHost = ledgerv4.SQLiteDirectIssueHost
type SQLiteDirectIssueAccess = ledgerv4.SQLiteDirectIssueAccess
type SQLiteDirectIssueConfig = ledgerv4.SQLiteDirectIssueConfig
type SQLiteDirectIssueStatus = ledgerv4.SQLiteDirectIssueStatus
type SQLiteDirectIssuePublication = ledgerv4.SQLiteDirectIssuePublication
type DirectIssueObligationState = ledgerv4.DirectIssueObligationState

const (
	DirectIssueReserved  = ledgerv4.DirectIssueReserved
	DirectIssueCommitted = ledgerv4.DirectIssueCommitted
	DirectIssueRetired   = ledgerv4.DirectIssueRetired
)

type SQLiteDirectIssueAuthority = ledgerv4.SQLiteDirectIssueAuthority

func SQLiteDirectIssueCharge(c SQLiteDirectIssueConfig) (resourcev4.Vector, error) {
	charge, err := ledgerv4.SQLiteDirectIssueCharge(c)
	return charge, v4IssueFailure(err)
}

func NewSQLiteDirectIssueAuthority(ctx context.Context, store *ledgerv4.SQLiteStore, c SQLiteDirectIssueConfig, reservation, dependencies resourcev4.Reference) (*SQLiteDirectIssueAuthority, error) {
	a, err := ledgerv4.NewSQLiteDirectIssueAuthority(ctx, store, c, reservation, dependencies)
	return a, v4IssueFailure(err)
}

// IssueFailure contains only bounded public categories, never provider text,
// caller authentication, secret material, signed documents or storage details.
type IssueFailure string

func (e IssueFailure) Error() string { return string(e) }

func v4IssueFailure(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return IssueFailure("cancelled")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, timev4.ErrExpired):
		return IssueFailure("expired")
	case errors.Is(err, resourcev4.ErrCapacity):
		return IssueFailure("capacity_exhausted")
	case errors.Is(err, resourcev4.ErrClosed):
		return IssueFailure("closed")
	case errors.Is(err, resourcev4.ErrConfiguration):
		return IssueFailure("configuration_invalid")
	default:
		return IssueFailure("issuance_refused")
	}
}

// DirectIssuer is an embeddable reference issuer for canonical direct/local
// v4 Artifacts. Host configuration fixes verified identities and route policy;
// a separate authenticated authority must durably reserve each original lease
// obligation before signing. It does not create activation or spend material.
type DirectIssuer struct{ inner *protocolv4.DirectIssuer }

func DirectIssuerCharge(c DirectIssuerConfig) (resourcev4.Vector, error) {
	charge, err := protocolv4.DirectIssuerCharge(c)
	if err == nil {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(DirectIssuer{}))})
	}
	return charge, v4IssueFailure(err)
}

func NewDirectIssuer(c DirectIssuerConfig, reservation, dependencies resourcev4.Reference) (*DirectIssuer, error) {
	charge, err := DirectIssuerCharge(c)
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
	return &DirectIssuer{inner: issuer}, nil
}

// IssueArtifactBytes requires a caller-reserved 65536-byte response buffer.
// Only the returned prefix is valid on success. The host delivers and erases
// these secret-bearing bytes through its independently authenticated channel.
func (s *DirectIssuer) IssueArtifactBytes(ctx context.Context, request DirectIssueRequest, dst []byte) (int, error) {
	if s == nil || s.inner == nil {
		return 0, IssueFailure("closed")
	}
	n, err := s.inner.IssueArtifactBytes(ctx, request, dst)
	return n, v4IssueFailure(err)
}

func (s *DirectIssuer) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}

func (s *DirectIssuer) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return IssueFailure("closed")
	}
	return v4IssueFailure(s.inner.WaitCleanup(ctx))
}

func (*DirectIssuer) String() string   { return "DirectIssuer(<redacted>)" }
func (*DirectIssuer) GoString() string { return "DirectIssuer(<redacted>)" }
