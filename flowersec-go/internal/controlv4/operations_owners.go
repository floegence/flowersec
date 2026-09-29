package controlv4

import (
	"context"
	"net/http"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// OperationsAuditStore is an explicitly registered transaction group. Access
// grants this service's fixed deployment scope only aggregate operations read;
// its independently retained authentication graph belongs to Dependencies.
// Registrations are immutable and bounded at eight; HTTP cannot select stores.
type OperationsAuditStore struct {
	Store  *ledgerv4.SQLiteTopUpServer
	Access ledgerv4.AuditAccess
}

type operationsStoreOwner struct {
	OperationsAuditStore
	pin resourcev4.Reference
}

type operationsStoreSnapshot struct {
	Slot         uint8                 `json:"slot"`
	State        string                `json:"state"`
	ReadDuration string                `json:"read_duration"`
	Audit        *ledgerv4.AuditStatus `json:"audit,omitempty"`
}

func (p *OperationsService) inspectStores(ctx context.Context, reader int, snapshot *operationsSnapshot, principals *[8]ledgerv4.AuditPrincipal) int {
	for i := range snapshot.Stores {
		if ctx.Err() != nil || !p.current(reader) {
			return http.StatusForbidden
		}
		owner := p.stores[i]
		principal, err := owner.Store.OperationsAuthorization(owner.Access)
		if err == ledgerv4.ErrAuditDenied {
			return http.StatusForbidden
		}
		principals[i] = principal
		out := operationsStoreSnapshot{Slot: uint8(i), State: "unavailable", ReadDuration: "other"}
		if err == nil {
			start := time.Now()
			audit, err := owner.Store.AuditStatus(ctx, owner.Access)
			out.ReadDuration = diagnosticv4.Duration(time.Since(start)).String()
			switch err {
			case nil:
				out.State, out.Audit = "available", &audit
			case ledgerv4.ErrAuditDenied:
				return http.StatusForbidden
			case ledgerv4.ErrAuditCapacity:
				out.State = "capacity"
			}
		}
		snapshot.Stores[i] = out
	}
	return http.StatusOK
}

func (p *OperationsService) storePermissionsCurrent(principals [8]ledgerv4.AuditPrincipal) bool {
	for i := 0; i < p.storeCount; i++ {
		// A failed owner supplied no privileged observation to publish.
		if principals[i] == (ledgerv4.AuditPrincipal{}) {
			continue
		}
		owner := p.stores[i]
		current, err := owner.Store.OperationsAuthorization(owner.Access)
		if err != nil || current != principals[i] {
			return false
		}
	}
	return true
}
