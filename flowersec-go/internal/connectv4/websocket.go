// Package connectv4 composes original Session owners with concrete providers.
package connectv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv4"
)

// WebSocketConsumerFactory is the numeric endpoint adapter used by the
// original source preparation. It reserves the provider before dialing from
// the same root and fixed original owner. Shared immutable
// header/TLS/route-policy backing belongs to SourceConnectConfig.Dependencies.
// The snapshot fixes a finite numeric address list per signed candidate. The
// original source selects an address ordinal; neither Dial nor this adapter
// resolves, races, retries or appends an address.
type WebSocketCandidate struct {
	Index uint64
	Dials []websocket.DialConfig
}

type WebSocketConsumerFactory struct {
	Candidates []WebSocketCandidate
	// PreparationWorkUnits is the qualified work ceiling for one configured
	// TLS/HTTP attempt, including its trusted route/policy checks.
	PreparationWorkUnits uint64
	Dial                 websocket.DialConfig
	Options              websocket.Options
	Root                 *resourcev4.Root
	Owner                resourcev4.OwnerKey
	Accounts             [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	AccountCount         uint8
	Environment          resourcev4.Reference
	DefaultPolicy        *WebSocketPolicy
	// CheckRoute binds every signed route/TLS/pin/consumer/Origin constraint to
	// this fixed Dial snapshot. It must be a bounded trusted deployment check,
	// with no I/O, application callback, or retention of the borrowed route.
	CheckRoute func(sessionv4.CarrierPreparationRequest, websocket.DialConfig) error
}

func (f WebSocketConsumerFactory) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (prepared *sessionv4.PreparedCarrier, err error) {
	if ctx == nil || f.Root == nil || (f.CheckRoute == nil) == (f.DefaultPolicy == nil) || request.Config.Deadline == nil || int(f.AccountCount) > len(f.Accounts) || request.Config.Environment != f.Environment || len(request.Route) == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	if request.Budget.PreauthBytes == 0 || request.Budget.WorkUnits < f.PreparationWorkUnits || f.PreparationWorkUnits == 0 || len(f.Candidates) > 16 {
		return nil, cryptov4.ErrConfiguration
	}
	dial := f.Dial
	if len(f.Candidates) == 0 {
		if request.AddressAttempt != 0 {
			return nil, sessionv4.ErrCandidateExhausted
		}
	} else {
		found := false
		var seen uint16
		for _, candidate := range f.Candidates {
			if candidate.Index >= 16 || seen&(1<<candidate.Index) != 0 || len(candidate.Dials) == 0 || len(candidate.Dials) > 8 {
				return nil, cryptov4.ErrConfiguration
			}
			seen |= 1 << candidate.Index
			if candidate.Index == request.Config.Candidate.Index {
				if int(request.AddressAttempt) >= len(candidate.Dials) {
					return nil, sessionv4.ErrCandidateExhausted
				}
				dial, found = candidate.Dials[request.AddressAttempt], true
			}
		}
		if !found {
			return nil, sessionv4.ErrCandidateExhausted
		}
	}
	if dial.PrepareBytes == 0 || dial.PrepareBytes > request.Budget.PreauthBytes {
		dial.PrepareBytes = request.Budget.PreauthBytes
	}
	charge, err := websocket.Charge(f.Options)
	if err != nil {
		return nil, err
	}
	if f.DefaultPolicy != nil {
		policyCharge, err := websocketPolicyCharge()
		if err != nil {
			return nil, err
		}
		charge, err = charge.Add(policyCharge)
		if err != nil {
			return nil, err
		}
	}
	if err = request.Config.Deadline.Check(); err != nil {
		return nil, err
	}
	if f.CheckRoute != nil {
		if err = f.CheckRoute(request, dial); err != nil {
			return nil, errors.Join(sessionv4.ErrCandidateExhausted, err)
		}
	}
	var identity [25]byte
	copy(identity[:16], f.Owner.Backing[:])
	binary.BigEndian.PutUint64(identity[16:24], request.Config.Candidate.Index)
	identity[24] = request.AddressAttempt
	digest := sha256.Sum256(identity[:])
	owner := f.Owner
	copy(owner.Backing[:], digest[:16])
	provider, err := f.Root.Reserve(owner, charge, f.Accounts[:f.AccountCount]...)
	if err != nil {
		return nil, err
	}
	defer provider.Release()
	if err = provider.CheckSameEnvironment(f.Environment); err != nil {
		return nil, err
	}
	var policy *policyMessages
	var policyBacking resourcev4.Reference
	adopted := false
	defer func() {
		if !adopted {
			policyBacking.Release()
		}
	}()
	if f.DefaultPolicy != nil {
		policyBacking, err = provider.Borrow()
		if err != nil {
			return nil, err
		}
		dial, policy, err = f.DefaultPolicy.prepare(request, dial, policyBacking)
		if err != nil {
			return nil, errors.Join(sessionv4.ErrCandidateExhausted, err)
		}
	}
	messages, err := websocket.Dial(ctx, dial, f.Options, provider, f.Environment)
	if err != nil {
		if errors.Is(err, websocket.ErrTLSHandshake) {
			return nil, errors.Join(sessionv4.ErrCandidateExhausted, err)
		}
		return nil, err
	}
	defer func() {
		if !adopted {
			// This is still the original prepare caller. Even panic/Goexit or
			// cancellation at wrapper construction joins the real provider.
			_ = messages.Close()
			_ = messages.WaitCleanup(context.Background())
			_ = messages.Retire()
		}
	}()
	if policy != nil {
		policy.Messages = messages
		prepared, err = sessionv4.NewPreparedMessages(ctx, request.Config, policy)
	} else {
		prepared, err = sessionv4.NewPreparedMessages(ctx, request.Config, messages)
	}
	adopted = err == nil
	return prepared, err
}
