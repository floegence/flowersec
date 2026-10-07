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

type LiveRelayReadAccess = ledgerv4.LiveTunnelSpendReadAccess

// This owner belongs to original in-process issuance, independently of the
// public registration read service below. Reading history cannot create it.
type SQLiteLiveRelayPublicationConfig = ledgerv4.SQLiteLiveRelayPublicationConfig
type SQLiteLiveRelayPublication = ledgerv4.SQLiteLiveRelayPublication

func SQLiteLiveRelayPublicationCharge() (resourcev4.Vector, error) {
	return ledgerv4.SQLiteLiveRelayPublicationCharge()
}

func NewSQLiteLiveRelayPublication(ctx context.Context, source *ledgerv4.SQLiteStore, plan *LiveActivationPlan, config SQLiteLiveRelayPublicationConfig) (*SQLiteLiveRelayPublication, error) {
	return ledgerv4.NewSQLiteLiveRelayPublication(ctx, source, plan, config)
}

// LiveRelayRegistrationService runs inside the trusted authority. It captures
// public relay registration facts only from complete original TxB history and
// owns a finite service share. Receipts retain original public evidence but no
// Artifact, secret or right to publish an allow, sign or activate a connection.
type LiveRelayRegistrationService struct{ inner *controlv4.LiveSpendService }

func LiveRelayRegistrationServiceCharges(c SpendReceiptServiceConfig) (service, read resourcev4.Vector, err error) {
	c.Tunnel = true
	service, read, err = controlv4.LiveSpendServiceCharges(c)
	if err == nil {
		service, err = service.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(LiveRelayRegistrationService{}))})
	}
	return
}

func NewLiveRelayRegistrationService(c SpendReceiptServiceConfig, reservation, read, dependencies resourcev4.Reference) (*LiveRelayRegistrationService, error) {
	c.Tunnel = true
	charge, _, err := LiveRelayRegistrationServiceCharges(c)
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
	return &LiveRelayRegistrationService{inner: s}, nil
}

func (s *LiveRelayRegistrationService) CaptureRelayLeg(ctx context.Context, access LiveRelayReadAccess, deadline *timev4.Deadline, expected ledgerv4.SQLiteIdentity, projection *protocolv4.RelayParentProjection, role protocolv4.Direction, reservation, dependencies resourcev4.Reference) (*ledgerv4.SQLiteCommittedRelayLeg, error) {
	if s == nil || s.inner == nil {
		return nil, SpendQueryFailure("unavailable")
	}
	r, err := s.inner.CaptureOriginalRelayLeg(ctx, access, deadline, expected, projection, role, reservation, dependencies)
	return r, controlv4.PublicSpendQueryFailure(err)
}

func (s *LiveRelayRegistrationService) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}

func (s *LiveRelayRegistrationService) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return SpendQueryFailure("unavailable")
	}
	return s.inner.WaitCleanup(ctx)
}
