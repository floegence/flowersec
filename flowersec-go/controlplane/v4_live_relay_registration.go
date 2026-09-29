package controlplane

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type V4LiveRelayReadAccess = ledgerv4.LiveTunnelSpendReadAccess

// This owner belongs to original in-process issuance, independently of the
// public registration read service below. Reading history cannot create it.
type V4SQLiteLiveRelayPublicationConfig = ledgerv4.SQLiteLiveRelayPublicationConfig
type V4SQLiteLiveRelayPublication = ledgerv4.SQLiteLiveRelayPublication

func V4SQLiteLiveRelayPublicationCharge() (resourcev4.Vector, error) {
	return ledgerv4.SQLiteLiveRelayPublicationCharge()
}

func NewV4SQLiteLiveRelayPublication(ctx context.Context, source *ledgerv4.SQLiteStore, plan *V4LiveActivationPlan, config V4SQLiteLiveRelayPublicationConfig) (*V4SQLiteLiveRelayPublication, error) {
	return ledgerv4.NewSQLiteLiveRelayPublication(ctx, source, plan, config)
}

// V4LiveRelayRegistrationService runs inside the trusted authority. It captures
// public relay registration facts only from complete original TxB history and
// owns a finite service share. Receipts retain original public evidence but no
// Artifact, secret or right to publish an allow, sign or activate a connection.
type V4LiveRelayRegistrationService struct{ inner *controlv4.LiveSpendService }

func V4LiveRelayRegistrationServiceCharges(c SpendReceiptServiceConfig) (service, read resourcev4.Vector, err error) {
	c.Tunnel = true
	service, read, err = controlv4.LiveSpendServiceCharges(c)
	if err == nil {
		service, err = service.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(V4LiveRelayRegistrationService{}))})
	}
	return
}

func NewV4LiveRelayRegistrationService(c SpendReceiptServiceConfig, reservation, read, dependencies resourcev4.Reference) (*V4LiveRelayRegistrationService, error) {
	c.Tunnel = true
	charge, _, err := V4LiveRelayRegistrationServiceCharges(c)
	if err != nil {
		return nil, controlv4.PublicSpendQueryFailure(err)
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, controlv4.PublicSpendQueryFailure(err)
	}
	defer owned.Release()
	s, err := controlv4.NewLiveSpendService(c, owned, read, dependencies)
	if err != nil {
		return nil, controlv4.PublicSpendQueryFailure(err)
	}
	return &V4LiveRelayRegistrationService{inner: s}, nil
}

func (s *V4LiveRelayRegistrationService) CaptureRelayLeg(ctx context.Context, access V4LiveRelayReadAccess, deadline *timev4.Deadline, expected ledgerv4.SQLiteIdentity, projection *protocolv4.RelayParentProjection, role protocolv4.Direction, reservation, dependencies resourcev4.Reference) (*ledgerv4.SQLiteCommittedRelayLeg, error) {
	if s == nil || s.inner == nil {
		return nil, SpendQueryFailure("unavailable")
	}
	r, err := s.inner.CaptureOriginalRelayLeg(ctx, access, deadline, expected, projection, role, reservation, dependencies)
	return r, controlv4.PublicSpendQueryFailure(err)
}

func (s *V4LiveRelayRegistrationService) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}

func (s *V4LiveRelayRegistrationService) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return SpendQueryFailure("unavailable")
	}
	return s.inner.WaitCleanup(ctx)
}
