package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"

// EnvironmentSnapshot has fixed cardinality and no identity, namespace list,
// endpoint, credential, provider handle, or application error. Counts include
// physical tails; logical closure alone does not free an occupied position.
// Independent management authorization belongs to the enclosing deployment
// service. This is not a public diagnostic projection or a cleanup receipt.
type EnvironmentSnapshot struct {
	Positions, Active, ServeGroups, ActiveServeGroups              uint32
	Materials, ActiveMaterials, MaterialPools, ActiveMaterialPools uint32
	Queries, ActiveQueries, Results, ActiveResults                 uint32
	ProtectedResults                                               uint32
	Controllers, ActiveControllers                                 uint32
	ServiceClients, ActiveServiceClients                           uint32
	BoundMethods, MaxBoundMethods                                  uint32
	Closed, CleanupComplete                                        bool
}

// BorrowOperations pins the original aggregate owner for a separately admitted
// management service. It conveys no authorization to expose a snapshot.
func (e *Environment) BorrowOperations(reservation resourcev4.Reference) (resourcev4.Reference, error) {
	if e == nil {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return resourcev4.Reference{}, resourcev4.ErrClosed
	}
	if err := e.reservation.CheckSameEnvironment(reservation); err != nil {
		return resourcev4.Reference{}, err
	}
	return e.reservation.Borrow()
}

func (e *Environment) OperationsSnapshot() EnvironmentSnapshot {
	if e == nil {
		return EnvironmentSnapshot{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	snapshot := e.operationsCaps
	snapshot.Active, snapshot.ActiveServeGroups = e.active, e.groupsActive
	snapshot.ActiveMaterials, snapshot.ActiveMaterialPools = e.materialActive, uint32(e.poolActive)
	snapshot.ActiveQueries, snapshot.ActiveResults = e.queryActive, e.resultActive
	for i := range e.results {
		if e.results[i].protected {
			snapshot.ProtectedResults++
		}
	}
	snapshot.Controllers, snapshot.ActiveControllers = uint32(len(e.controllers)), e.controllersActive
	snapshot.ServiceClients, snapshot.ActiveServiceClients = uint32(len(e.serviceClients)), uint32(e.serviceClientActive)
	snapshot.BoundMethods, snapshot.MaxBoundMethods = uint32(e.boundMethods), uint32(e.maxBoundMethods)
	snapshot.Closed, snapshot.CleanupComplete = e.closed, e.cleaned
	return snapshot
}
