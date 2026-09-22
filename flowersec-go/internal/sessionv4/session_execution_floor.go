package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type rpcExecutionScope struct {
	accounts [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	count    int
}

func executionChargeStart(c RPCServicesConfig) (int, error) {
	c, geometry, err := c.futureConfig()
	if err != nil {
		return 0, err
	}
	position := rpcServicesOwners
	for channel := uint32(1); channel < geometry.RPC+geometry.Notify+geometry.Management; channel++ {
		_, count, err := futureChannelCharges(c, channel)
		if err != nil {
			return 0, err
		}
		position += count
	}
	return position, nil
}

func appendExecutionFloorCharges(c RPCServicesConfig, charges *[rpcServicesOwnerCapacity]resourcev4.Vector, position int) error {
	if len(c.ExecutionServices) == 0 {
		return nil
	}
	if c.Session.Limits().ApplicationProfile != "execution" {
		return cryptov4.ErrConfiguration
	}
	output, err := executionFloorCallCharges(c.InvocationRuntimeBytes, c.ShortResponseBytes, c.ExecutionServices)
	if err != nil {
		return err
	}
	for _, vector := range output {
		charges[position], err = resourcev4.ProtectedCharge(vector)
		if err != nil {
			return err
		}
		position++
	}
	for _, binding := range c.ExecutionServices {
		var vectors [4]resourcev4.Vector
		var err error
		if binding.DurableHistory != nil {
			vectors, err = binding.DurableHistory.ShortAdmissionCharges(c.ShortResponseBytes, c.InvocationRuntimeBytes)
		} else {
			vectors, err = binding.History.ShortAdmissionCharges(c.ShortResponseBytes, c.InvocationRuntimeBytes)
		}
		if err != nil {
			return err
		}
		for _, vector := range vectors {
			charges[position] = vector
			position++
		}
	}
	return nil
}

func prepareExecutionScopes(c RPCServicesConfig) ([]rpcExecutionScope, int, error) {
	position, err := executionChargeStart(c)
	if err != nil {
		return nil, 0, err
	}
	scopes := make([]rpcExecutionScope, len(c.ExecutionServices))
	for i, binding := range c.ExecutionServices {
		if binding.DurableHistory != nil {
			scopes[i].count, err = binding.DurableHistory.AdmissionAccounts(c.Root, c.Owner, &scopes[i].accounts)
		} else {
			scopes[i].count, err = binding.History.AdmissionAccounts(c.Root, c.Owner, &scopes[i].accounts)
		}
		if err != nil {
			return nil, 0, err
		}
	}
	return scopes, position, nil
}

func (b *rpcServicesBatch) accountsFor(index int) []resourcev4.Account {
	if len(b.executionScopes) != 0 && index >= b.executionStart+5 {
		scope := &b.executionScopes[(index-b.executionStart-5)/4]
		return scope.accounts[:scope.count]
	}
	return b.config.Accounts
}

func (b *rpcServicesBatch) installExecutionReferences(c *ServiceDispatchConfig, r *RPCServices) {
	if len(b.config.ExecutionServices) == 0 {
		return
	}
	position := b.executionStart
	copy(c.ShortExecutionReservations[:], r.refs[position:position+5])
	position += 5
	c.ShortExecutionAdmissions = make([][4]resourcev4.Reference, len(b.config.ExecutionServices))
	for i := range c.ShortExecutionAdmissions {
		copy(c.ShortExecutionAdmissions[i][:], r.refs[position:position+4])
		position += 4
	}
}
