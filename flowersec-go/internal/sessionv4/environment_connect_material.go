package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// MaterialConnectConfig is the private static-input projection of the common
// preparation recipe. Identity, Provider, Acquisition, Material and
// MaterialRuntimeBytes must be absent: the original hosted material already
// owns that complete identity/lease pair and its finite lifetime. Generation
// must match that snapshot. All remaining preparation/admission owners are the
// same as in source acquisition; there is no second connection engine.
type MaterialConnectConfig SourceConnectConfig

// The original preparation watcher checks this local gate without key calls.
// Material closure/expiry prevents a new attachment; an establishment that has
// already taken its captured references keeps its independent security gates.
func (m *ConnectionMaterial) checkPreparationOpen() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed && !m.attached {
		return cryptov4.ErrClosed
	}
	return nil
}

// ConnectMaterialPool transfers a static material hosted by this Environment
// only after local Session-position and configuration admission. Local refusal
// preserves caller ownership. Once accepted, the original worker owns material,
// candidate selection and cleanup through the same pool spend/READY path.
func (e *Environment) ConnectMaterialPool(ctx context.Context, material *ConnectionMaterial, options MaterialConnectConfig, spend PoolSessionInput) (*EnvironmentSession, error) {
	c := SourceConnectConfig(options)
	if material == nil || spend.Store == nil || spend.Authority == nil || spend.Establishment != nil || spend.Admission != nil || c.LiveIssuance.Signer != nil {
		return nil, cryptov4.ErrConfiguration
	}
	return e.startSource(ctx, c, environmentEstablishment{kind: 1, pool: spend}, material)
}

// ConnectMaterialLiveSQLite is the distinct in-process live-authority variant.
// Its unchanged original TxA/TxB path may bind only this preparation's winner.
// Pool input never enters this variant and errors never switch source profile.
func (e *Environment) ConnectMaterialLiveSQLite(ctx context.Context, material *ConnectionMaterial, options MaterialConnectConfig, spend LiveSessionInput) (*EnvironmentSession, error) {
	c := SourceConnectConfig(options)
	if material == nil || spend.Store == nil || spend.Authority == nil || (spend.Issuance == nil) == (c.LiveIssuance.Signer == nil) || spend.Guard == nil || spend.Policy == nil || spend.Establishment != nil || spend.Admission != nil {
		return nil, cryptov4.ErrConfiguration
	}
	return e.startSource(ctx, c, environmentEstablishment{kind: 2, live: spend}, material)
}
