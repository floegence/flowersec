package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type ServiceContractTarget = sessionv4.ServiceContractTarget
type ContractQuerySnapshots = sessionv4.ContractQuerySnapshots
type ContractQuerySnapshotInfo = protocolv4.ContractSnapshotInfo
type ServiceContractPolicy = protocolv4.ServiceContractPolicy
type AdmissionOfferBounds = protocolv4.AdmissionOfferBounds
type ContractQueryRefusal = sessionv4.ContractQueryRefusal

// QueryTargetAccess controls discovery through one authenticated application
// lease. Allowing a query does not grant execution or install a contract.
type QueryTargetAccess = rpcv4.QueryTargetAccess

const (
	QueryTargetUnavailable = rpcv4.QueryTargetUnavailable
	QueryTargetDenied      = rpcv4.QueryTargetDenied
	QueryTargetAllowed     = rpcv4.QueryTargetAllowed
)

// QueryServiceContracts reads one finite batch of one to eight explicit targets
// through an already accepted ordinary RPC channel. Close the returned owned
// snapshots after use. These authenticated bytes do not install a service,
// approve a contract update, extend authorization or grant execution rights.
func (s *Session) QueryServiceContracts(ctx context.Context, targets []ServiceContractTarget) (*ContractQuerySnapshots, error) {
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
