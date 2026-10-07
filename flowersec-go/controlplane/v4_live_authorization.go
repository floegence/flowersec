package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type LiveAuthorizationRequest = sessionv4.LiveAuthorizationRequest
type LiveAuthorizationCodec = controlv4.LiveAuthorizationCodec

// LiveAuthorizationCodecBackingBytes is admitted by the host before creating
// a codec; HTTP server/request owners also bound header/body work and tasks.
func LiveAuthorizationCodecBackingBytes() (uint64, error) {
	return controlv4.LiveAuthorizationCodecBackingBytes()
}

func NewLiveAuthorizationCodec() (*LiveAuthorizationCodec, error) {
	return controlv4.NewLiveAuthorizationCodec()
}

func EncodeLiveAuthorizationRequest(dst []byte, request LiveAuthorizationRequest) (int, error) {
	return controlv4.EncodeLiveAuthorizationRequest(dst, request)
}

// Issuance plans remain in the trusted authority. Consumers receive only
// original signed material through their independently configured provider.
type LiveActivationPlan = protocolv4.LiveActivationPlan
type LiveActivationConfig = protocolv4.LiveActivationConfig
type LiveTunnelActivationConfig = protocolv4.LiveTunnelActivationConfig
type LiveGrantProjection = protocolv4.LiveGrantProjection
type LiveGrantIssuance = protocolv4.LiveGrantIssuance
type LiveGrantPreparationConfig = protocolv4.LiveGrantPreparationConfig
type PoolActivationConfig = protocolv4.PoolActivationConfig
type PoolActivationPlan = protocolv4.PoolActivationPlan
type PoolAttemptLimits = protocolv4.PoolAttemptLimits

func DeriveLiveGrantPreparation(parent *protocolv4.Credential, role protocolv4.Direction, validation protocolv4.CredentialValidation, config LiveGrantPreparationConfig, environment resourcev4.Reference) (protocolv4.LiveGrantPreparation, error) {
	return protocolv4.DeriveLiveGrantPreparation(parent, role, validation, config, environment)
}

func LiveActivationPlanCharge(tunnel ...bool) (resourcev4.Vector, error) {
	return protocolv4.LiveActivationPlanCharge(tunnel...)
}

func NewLiveActivationPlan(artifact *protocolv4.SignedMap, rules *protocolv4.NamespaceRules, delegation, once []byte, signer protocolv4.MapSigner, config LiveActivationConfig, reservation, environment, materialOwner resourcev4.Reference) (*LiveActivationPlan, error) {
	return protocolv4.NewLiveActivationPlan(artifact, rules, delegation, once, signer, config, reservation, environment, materialOwner)
}

func PoolActivationPlanCharge(config PoolActivationConfig) (resourcev4.Vector, error) {
	return protocolv4.PoolActivationPlanCharge(config)
}

func PoolActivationPlanCapacity(tunnels uint8) (resourcev4.Vector, error) {
	return protocolv4.PoolActivationPlanCapacity(tunnels)
}

func NewPoolActivationPlan(artifact *protocolv4.SignedMap, rules *protocolv4.NamespaceRules, delegation, once []byte, signer protocolv4.MapSigner, config PoolActivationConfig, reservation, environment, materialOwner resourcev4.Reference) (*PoolActivationPlan, error) {
	return protocolv4.NewPoolActivationPlan(artifact, rules, delegation, once, signer, config, reservation, environment, materialOwner)
}
