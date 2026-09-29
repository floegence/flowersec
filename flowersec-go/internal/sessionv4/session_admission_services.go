package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// sessionAdmissionBatch keeps transport and application backing in the same
// original admission transaction. Its scratch cannot escape construction; the
// resulting owners retain only their admitted references and copied settings.
type sessionAdmissionBatch struct {
	preauth, sessionSlot resourcev4.Reference
	role                 protocolv4.Direction
	core                 sessionCoreBatch
	rpc                  rpcServicesBatch
	count                int
}

const sessionAdmissionOwnerCapacity = coreOwnerCapacity + rpcServicesOwnerCapacity

func (b *sessionAdmissionBatch) prepare(c SessionAdmissionConfig, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, scope SessionResourceScope, accounts ...resourcev4.Account) error {
	b.role = c.Initial.Role
	core, err := admissionCoreConfig(c)
	if err != nil {
		return err
	}
	if err := describeSessionCoreBatch(&b.core, core, root, owner, environment, scope, accounts...); err != nil {
		return err
	}
	if c.headroom == nil {
		if err := b.core.reserveEnvironmentBorrows(); err != nil {
			return err
		}
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
	if _, _, err := sessionStreamWorkloadRequirements(core, rpc, b.role); err != nil {
		b.release()
		return err
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
	b.preauth.Release()
	b.sessionSlot.Release()
	b.preauth, b.sessionSlot = resourcev4.Reference{}, resourcev4.Reference{}
	b.rpc.release()
	b.core.release()
}

func (b *sessionAdmissionBatch) adopt(a *SessionAdmissionReservation, refs []resourcev4.Reference) error {
	if len(refs) != b.count {
		return resourcev4.ErrOwner
	}
	if a.config.Core.Native {
		if a.prepared == nil || a.prepared.native == nil {
			return cryptov4.ErrConfiguration
		}
		b.core.nativeConnection = a.prepared.native
	}
	if b.rpc.built != nil {
		if err := b.rpc.built.prepareWorkloadProviders(b.core.nativeConnection); err != nil {
			return err
		}
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
	if len(refs) != b.count {
		return resourcev4.ErrOwner
	}
	ref := refs[b.core.count+rpcServicesDeliveryFloor]
	c := b.rpc.config
	var err error
	if b.rpc.deliveryFloor != nil {
		err = b.rpc.deliveryFloor.BindSubscriptions(subscriptions)
	} else {
		if err = ref.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err == nil {
			b.rpc.deliveryFloor, err = subscriptions.ReserveDeliveryFloor(ref)
		}
	}
	if err != nil {
		return err
	}
	b.rpc.plan.mu.Lock()
	host := b.rpc.plan.host
	b.rpc.plan.mu.Unlock()
	if host != nil {
		host.mu.Lock()
		environment, closed := host.environment, host.closed
		host.mu.Unlock()
		if closed || environment == nil {
			return cryptov4.ErrClosed
		}
		if b.rpc.resultPosition == (environmentResultProtection{}) {
			b.rpc.resultPosition, err = environment.protectResult(refs[b.core.count+rpcServicesCallerOwner])
			if err != nil {
				return err
			}
		} else {
			if b.rpc.resultPosition.environment != environment {
				return resourcev4.ErrOwner
			}
			environment.mu.Lock()
			_, err = b.rpc.resultPosition.slotLocked()
			if environment.closed || environment.retired {
				err = cryptov4.ErrClosed
			}
			environment.mu.Unlock()
			if err != nil {
				return err
			}
		}
	} else if b.rpc.resultPosition != (environmentResultProtection{}) {
		return resourcev4.ErrOwner
	}
	if len(c.Workloads) != 0 || b.rpc.initializer != nil {
		if err := b.core.prepareReceivePool(refs[:b.core.count]); err != nil {
			return err
		}
		if len(c.Workloads) != 0 && b.rpc.workloadHeadroom == nil {
			if host == nil {
				return cryptov4.ErrConfiguration
			}
			host.mu.Lock()
			environment := host.environment
			host.mu.Unlock()
			if environment == nil {
				return cryptov4.ErrClosed
			}
			h := sessionHeadroom{receivePool: b.core.receivePool}
			err := h.reserveWorkloads(c, b.core.config, b.role, b.rpc.plan, environment)
			b.rpc.workloadHeadroom = h.workloads
			if err != nil {
				return err
			}
		}
		r, err := b.rpc.build(refs[b.core.count:])
		if err != nil {
			return err
		}
		if err := r.reserveInitialSessionWorkloads(c.Workloads, subscriptions, &b.rpc.workloadHeadroom); err != nil {
			return err
		}
		return b.rpc.initializer.install(r, subscriptions, &b.rpc.initializerWorkloads)
	}
	return nil
}
