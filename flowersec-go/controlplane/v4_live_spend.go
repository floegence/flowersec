package controlplane

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type SpendReceipt = ledgerv4.SpendReceipt
type SpendQueryFailure = controlv4.SpendQueryFailure
type SpendReceiptServiceConfig = controlv4.LiveSpendServiceConfig

// SpendReceiptService exposes independently authenticated read-only facts.
// Mount it in a bounded application query or login-authorized HTTPS handler.
// The host supplies access from authenticated tenant/identity/audience context;
// request payloads alone cannot authorize a lookup. No public material getter,
// automatic recovery, callback, or activation authority is provided.
type SpendReceiptService struct{ inner *controlv4.LiveSpendService }

func SpendReceiptServiceCharges(c SpendReceiptServiceConfig) (service, read resourcev4.Vector, err error) {
	service, read, err = controlv4.LiveSpendServiceCharges(c)
	if err == nil {
		service, err = service.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SpendReceiptService{}))})
	}
	return
}

func NewSpendReceiptService(c SpendReceiptServiceConfig, reservation, readReservation, dependencies resourcev4.Reference) (*SpendReceiptService, error) {
	charge, _, err := SpendReceiptServiceCharges(c)
	if err != nil {
		return nil, controlv4.PublicSpendQueryFailure(err)
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, controlv4.PublicSpendQueryFailure(err)
	}
	defer owned.Release()
	service, err := controlv4.NewLiveSpendService(c, owned, readReservation, dependencies)
	if err != nil {
		return nil, controlv4.PublicSpendQueryFailure(err)
	}
	return &SpendReceiptService{inner: service}, nil
}

func (s *SpendReceiptService) QuerySpendReceipt(ctx context.Context, access ledgerv4.LiveSpendReadAccess, deadline *timev4.Deadline) (SpendReceipt, error) {
	if s == nil || s.inner == nil {
		return SpendReceipt{}, SpendQueryFailure("unavailable")
	}
	r, err := s.inner.QuerySpendReceipt(ctx, access, deadline)
	return r, controlv4.PublicSpendQueryFailure(err)
}

// QuerySpendReceiptBytes emits the same facts in the shared canonical CBOR map.
// The caller reserves at least 61 output bytes and retains its own authenticated
// response/signature owner. No provider text is returned on failure.
func (s *SpendReceiptService) QuerySpendReceiptBytes(ctx context.Context, access ledgerv4.LiveSpendReadAccess, deadline *timev4.Deadline, dst []byte) (int, error) {
	if s == nil || s.inner == nil {
		return 0, SpendQueryFailure("unavailable")
	}
	n, err := s.inner.QuerySpendReceiptBytes(ctx, access, deadline, dst)
	return n, controlv4.PublicSpendQueryFailure(err)
}

func (s *SpendReceiptService) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}

func (s *SpendReceiptService) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return SpendQueryFailure("unavailable")
	}
	return s.inner.WaitCleanup(ctx)
}
