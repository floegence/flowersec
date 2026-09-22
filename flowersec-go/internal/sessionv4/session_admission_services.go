package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// sessionAdmissionBatch keeps transport and application backing in the same
// original admission transaction. Its scratch cannot escape construction; the
// resulting owners retain only their admitted references and copied settings.
type sessionAdmissionBatch struct {
	core  sessionCoreBatch
	rpc   rpcServicesBatch
	count int
}

const sessionAdmissionOwnerCapacity = coreOwnerCapacity + rpcServicesOwnerCapacity

func (b *sessionAdmissionBatch) prepare(c SessionAdmissionConfig, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, scope SessionResourceScope, accounts ...resourcev4.Account) error {
	core, err := admissionCoreConfig(c)
	if err != nil {
		return err
	}
	if err := prepareSessionCoreBatch(&b.core, core, root, owner, environment, scope, accounts...); err != nil {
		return err
	}
	b.count = b.core.count
	if c.RPC == nil {
		return nil
	}
	rpc := *c.RPC
	if c.Application == nil || rpc.Session != c.Core.Session.Contract || rpc.Clock != c.Core.Clock || rpc.CryptoProfile != c.Core.Session.Profile || rpc.MaxDataPayloadBytes != c.Core.MaxDataPayloadBytes {
		b.release()
		return cryptov4.ErrConfiguration
	}
	// The original verified tenant/Session scope is authoritative for all RPC
	// children. A template cannot inject a second budget root or omit accounts.
	rpc.Root, rpc.Owner, rpc.Accounts = root, owner, b.core.accounts[:b.core.accountCount]
	if err := prepareRPCServicesBatch(&b.rpc, c.Application, rpc, c.applicationHost); err != nil {
		b.release()
		return err
	}
	b.count += b.rpc.count
	return nil
}

func (b *sessionAdmissionBatch) request(index int) (resourcev4.Request, error) {
	if index < b.core.count {
		return b.core.request(index)
	}
	return b.rpc.request(index - b.core.count)
}

func (b *sessionAdmissionBatch) release() {
	b.rpc.release()
	b.core.release()
}

func (b *sessionAdmissionBatch) adopt(a *SessionAdmissionReservation, refs []resourcev4.Reference) error {
	if len(refs) != b.count {
		return resourcev4.ErrOwner
	}
	if err := b.core.prepareReceivePool(refs[:b.core.count]); err != nil {
		return err
	}
	if b.rpc.prepared {
		rpc, err := b.rpc.adopt(refs[b.core.count:])
		b.rpc.release()
		if err != nil {
			return err
		}
		if err := rpc.prepareReceive(b.core.receivePool); err != nil {
			a.config.Application.Close()
			return err
		}
	}
	if err := a.adoptApplicationCore(&b.core, refs[:b.core.count]); err != nil {
		if a.config.RPC != nil {
			a.config.Application.Close()
		}
		return err
	}
	if a.application != nil {
		a.core.rpc = a.application.rpc
		a.core.application = a.application
	}
	// No caller-owned assembly pointer survives the original construction.
	a.config.RPC = nil
	return nil
}

// The exact original role-specific namespace references are admitted before
// credential adoption/TxA, alongside all RPC bytes and future result owners.
func (b *sessionAdmissionBatch) reserveDeliveryFloor(subscriptions *protocolv4.CredentialSubscriptions, refs []resourcev4.Reference) error {
	if !b.rpc.prepared {
		return nil
	}
	if len(refs) != b.count || b.rpc.deliveryFloor != nil {
		return resourcev4.ErrOwner
	}
	ref := refs[b.core.count+rpcServicesDeliveryFloor]
	c := b.rpc.config
	if err := ref.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return err
	}
	floor, err := subscriptions.ReserveDeliveryFloor(ref)
	if err != nil {
		return err
	}
	b.rpc.deliveryFloor = floor
	return nil
}
