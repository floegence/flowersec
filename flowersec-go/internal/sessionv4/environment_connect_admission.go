package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

// ConnectPrepared uses the original connection preparation and reports the
// local ownership handoff independently of delivery. A canceled delivery may
// return no Session while the admitted original position still owns provider
// tails, the application plan and every supplied workspace. Only admitted=false
// permits the assembly caller to dispose its unused preparations.
// Exactly one authority variant is required; failures never try another.
func (e *Environment) ConnectPrepared(ctx context.Context, c SourceConnectConfig, material *ConnectionMaterial, pool *PoolSessionInput, live *LiveSessionInput) (*EnvironmentSession, bool, error) {
	if (pool == nil) == (live == nil) {
		return nil, false, cryptov4.ErrConfiguration
	}
	var input environmentEstablishment
	if pool != nil {
		if pool.Store == nil || pool.Authority == nil || pool.Establishment != nil || pool.Admission != nil || c.LiveIssuance.Signer != nil {
			return nil, false, cryptov4.ErrConfiguration
		}
		input = environmentEstablishment{kind: 1, pool: *pool}
	} else {
		if !live.validAuthority(c.LiveIssuance.Signer != nil) || live.Establishment != nil || live.Admission != nil {
			return nil, false, cryptov4.ErrConfiguration
		}
		input = environmentEstablishment{kind: 2, live: *live}
	}
	return e.startSourcePrepared(ctx, c, input, material)
}

// ConnectPoolSource keeps the local pool acquisition under the same original
// admitted Session position as preparation and spend. Empty pools return their
// explicit source result; acquisition never starts or joins a TopUp.
func (e *Environment) ConnectPoolSource(ctx context.Context, source *PreauthorizedPoolSource, c SourceConnectConfig, spend PoolSessionInput) (*EnvironmentSession, bool, error) {
	if source == nil || c.Generation != (MaterialGeneration{}) {
		return nil, false, cryptov4.ErrConfiguration
	}
	c.poolSource = source
	return e.ConnectPrepared(ctx, c, nil, &spend, nil)
}
