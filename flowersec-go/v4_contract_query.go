package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type V4ServiceContractTarget = sessionv4.ServiceContractTarget
type V4ContractQuerySnapshots = sessionv4.ContractQuerySnapshots
type V4ContractQuerySnapshotInfo = protocolv4.ContractSnapshotInfo
type V4ServiceContractPolicy = protocolv4.ServiceContractPolicy
type V4AdmissionOfferBounds = protocolv4.AdmissionOfferBounds
type V4ContractQueryRefusal = sessionv4.ContractQueryRefusal

// QueryServiceContracts reads one finite batch of one to eight explicit targets
// through an already accepted ordinary RPC channel. Close the returned owned
// snapshots after use. These authenticated bytes do not install a service,
// approve a contract update, extend authorization or grant execution rights.
func (s *V4Session) QueryServiceContracts(ctx context.Context, targets []V4ServiceContractTarget) (*V4ContractQuerySnapshots, error) {
	if s == nil || ctx == nil {
		return nil, ErrTransportUnavailable
	}
	s.mu.Lock()
	closed, query := s.closed, s.queryServiceContracts
	s.mu.Unlock()
	if closed {
		return nil, ErrOperationClosed
	}
	if query == nil {
		return nil, ErrTransportUnavailable
	}
	return query(ctx, targets)
}
