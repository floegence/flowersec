package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type V4LiveAuthorizationRequest = sessionv4.LiveAuthorizationRequest
type V4LiveAuthorizationCodec = controlv4.LiveAuthorizationCodec

// V4LiveAuthorizationCodecBackingBytes is admitted by the host before creating
// a codec; HTTP server/request owners also bound header/body work and tasks.
func V4LiveAuthorizationCodecBackingBytes() (uint64, error) {
	return controlv4.LiveAuthorizationCodecBackingBytes()
}

func NewV4LiveAuthorizationCodec() (*V4LiveAuthorizationCodec, error) {
	return controlv4.NewLiveAuthorizationCodec()
}

func EncodeV4LiveAuthorizationRequest(dst []byte, request V4LiveAuthorizationRequest) (int, error) {
	return controlv4.EncodeLiveAuthorizationRequest(dst, request)
}

// Issuance plans remain in the trusted authority. Consumers receive only
// original signed material through their independently configured provider.
type V4LiveActivationPlan = protocolv4.LiveActivationPlan
type V4LiveActivationConfig = protocolv4.LiveActivationConfig
type V4LiveTunnelActivationConfig = protocolv4.LiveTunnelActivationConfig
type V4LiveGrantProjection = protocolv4.LiveGrantProjection
type V4LiveGrantIssuance = protocolv4.LiveGrantIssuance
type V4LiveGrantPreparationConfig = protocolv4.LiveGrantPreparationConfig
type V4PoolActivationConfig = protocolv4.PoolActivationConfig
type V4PoolActivationPlan = protocolv4.PoolActivationPlan
type V4PoolAttemptLimits = protocolv4.PoolAttemptLimits

func DeriveV4LiveGrantPreparation(parent *protocolv4.Credential, role protocolv4.Direction, validation protocolv4.CredentialValidation, config V4LiveGrantPreparationConfig, environment resourcev4.Reference) (protocolv4.LiveGrantPreparation, error) {
	return protocolv4.DeriveLiveGrantPreparation(parent, role, validation, config, environment)
}

func V4LiveActivationPlanCharge(tunnel ...bool) (resourcev4.Vector, error) {
	return protocolv4.LiveActivationPlanCharge(tunnel...)
}

func NewV4LiveActivationPlan(artifact *protocolv4.SignedMap, rules *protocolv4.NamespaceRules, delegation, once []byte, signer protocolv4.MapSigner, config V4LiveActivationConfig, reservation, environment, materialOwner resourcev4.Reference) (*V4LiveActivationPlan, error) {
	return protocolv4.NewLiveActivationPlan(artifact, rules, delegation, once, signer, config, reservation, environment, materialOwner)
}

func V4PoolActivationPlanCharge(config V4PoolActivationConfig) (resourcev4.Vector, error) {
	return protocolv4.PoolActivationPlanCharge(config)
}

func V4PoolActivationPlanCapacity(tunnels uint8) (resourcev4.Vector, error) {
	return protocolv4.PoolActivationPlanCapacity(tunnels)
}

func NewV4PoolActivationPlan(artifact *protocolv4.SignedMap, rules *protocolv4.NamespaceRules, delegation, once []byte, signer protocolv4.MapSigner, config V4PoolActivationConfig, reservation, environment, materialOwner resourcev4.Reference) (*V4PoolActivationPlan, error) {
	return protocolv4.NewPoolActivationPlan(artifact, rules, delegation, once, signer, config, reservation, environment, materialOwner)
}
