package channelinit

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"github.com/flowersec/flowersec/controlplane/issuer"
	"github.com/flowersec/flowersec/controlplane/token"
	controlv1 "github.com/flowersec/flowersec/gen/flowersec/controlplane/v1"
	e2eev1 "github.com/flowersec/flowersec/gen/flowersec/e2ee/v1"
	"github.com/flowersec/flowersec/internal/base64url"
)

const (
	// ChannelInitWindowSeconds bounds how long a grant remains valid.
	ChannelInitWindowSeconds = 120
	// IdleTimeoutSeconds advertises the server idle timeout to clients.
	IdleTimeoutSeconds = 60
	// DefaultTokenExpSeconds is used when TokenExpSeconds is unset.
	DefaultTokenExpSeconds = 60
)

// Params define channel-init issuance settings and defaults.
type Params struct {
	TunnelURL      string // WebSocket URL for tunnel server.
	TunnelAudience string // Expected audience for issued tokens.
	IssuerID       string // Issuer identifier embedded in tokens.

	TokenExpSeconds int64         // Token lifetime in seconds (capped by init exp).
	ClockSkew       time.Duration // Allowed clock skew for validation hints.

	AllowedSuites []e2eev1.Suite // E2EE suites permitted for the channel.
	DefaultSuite  e2eev1.Suite   // Default E2EE suite for the channel.
}

// Service issues channel-init grants and tokens for clients/servers.
type Service struct {
	Issuer *issuer.Keyset   // Signing keyset for tunnel tokens.
	Params Params           // Defaults and limits for channel-init grants.
	Now    func() time.Time // Optional time source override.
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// NewChannelInit creates paired client/server grants with shared PSK and tokens.
func (s *Service) NewChannelInit(channelID string) (client *controlv1.ChannelInitGrant, server *controlv1.ChannelInitGrant, err error) {
	if s.Issuer == nil {
		return nil, nil, errors.New("missing issuer")
	}
	if s.Params.TunnelURL == "" || s.Params.TunnelAudience == "" {
		return nil, nil, errors.New("missing tunnel params")
	}
	if channelID == "" {
		return nil, nil, errors.New("missing channel_id")
	}
	psk, err := randomBytes(32)
	if err != nil {
		return nil, nil, err
	}
	pskB64u := base64url.Encode(psk)

	now := s.now()
	initExp := now.Add(ChannelInitWindowSeconds * time.Second).Unix()
	tokenExpSeconds := s.Params.TokenExpSeconds
	if tokenExpSeconds <= 0 {
		tokenExpSeconds = DefaultTokenExpSeconds
	}

	allowedSuitesE2EE := s.Params.AllowedSuites
	if len(allowedSuitesE2EE) == 0 {
		allowedSuitesE2EE = []e2eev1.Suite{e2eev1.Suite_X25519_HKDF_SHA256_AES_256_GCM}
	}
	allowedSuites := make([]controlv1.Suite, 0, len(allowedSuitesE2EE))
	for _, s := range allowedSuitesE2EE {
		allowedSuites = append(allowedSuites, controlv1.Suite(s))
	}
	defaultSuiteE2EE := s.Params.DefaultSuite
	if defaultSuiteE2EE == 0 {
		defaultSuiteE2EE = e2eev1.Suite_X25519_HKDF_SHA256_AES_256_GCM
	}
	defaultSuite := controlv1.Suite(defaultSuiteE2EE)

	clientToken, err := s.signRoleToken(channelID, uint8(controlv1.Role_client), initExp, tokenExpSeconds, now)
	if err != nil {
		return nil, nil, err
	}
	serverToken, err := s.signRoleToken(channelID, uint8(controlv1.Role_server), initExp, tokenExpSeconds, now)
	if err != nil {
		return nil, nil, err
	}

	client = &controlv1.ChannelInitGrant{
		TunnelUrl:                s.Params.TunnelURL,
		ChannelId:                channelID,
		ChannelInitExpireAtUnixS: initExp,
		IdleTimeoutSeconds:       IdleTimeoutSeconds,
		Role:                     controlv1.Role_client,
		Token:                    clientToken,
		E2eePskB64u:              pskB64u,
		AllowedSuites:            allowedSuites,
		DefaultSuite:             defaultSuite,
	}
	server = &controlv1.ChannelInitGrant{
		TunnelUrl:                s.Params.TunnelURL,
		ChannelId:                channelID,
		ChannelInitExpireAtUnixS: initExp,
		IdleTimeoutSeconds:       IdleTimeoutSeconds,
		Role:                     controlv1.Role_server,
		Token:                    serverToken,
		E2eePskB64u:              pskB64u,
		AllowedSuites:            allowedSuites,
		DefaultSuite:             defaultSuite,
	}
	return client, server, nil
}

// ReissueToken refreshes the signed token while keeping the same grant fields.
func (s *Service) ReissueToken(grant *controlv1.ChannelInitGrant) (*controlv1.ChannelInitGrant, error) {
	if grant == nil {
		return nil, errors.New("missing grant")
	}
	now := s.now()
	tokenExpSeconds := s.Params.TokenExpSeconds
	if tokenExpSeconds <= 0 {
		tokenExpSeconds = DefaultTokenExpSeconds
	}
	role := uint8(grant.Role)
	newToken, err := s.signRoleToken(grant.ChannelId, role, grant.ChannelInitExpireAtUnixS, tokenExpSeconds, now)
	if err != nil {
		return nil, err
	}
	out := *grant
	out.Token = newToken
	return &out, nil
}

func (s *Service) signRoleToken(channelID string, role uint8, initExp int64, tokenExpSeconds int64, now time.Time) (string, error) {
	tokenID, err := randomB64u(24)
	if err != nil {
		return "", err
	}
	iat := now.Unix()
	exp := now.Add(time.Duration(tokenExpSeconds) * time.Second).Unix()
	if exp > initExp {
		exp = initExp
	}
	return s.Issuer.SignToken(token.Payload{
		Aud:       s.Params.TunnelAudience,
		Iss:       s.Params.IssuerID,
		ChannelID: channelID,
		Role:      role,
		TokenID:   tokenID,
		InitExp:   initExp,
		Iat:       iat,
		Exp:       exp,
	})
}

func randomB64u(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return base64url.Encode(b), nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// MarshalGrantJSON encodes the grant for transport to the client.
func MarshalGrantJSON(g *controlv1.ChannelInitGrant) ([]byte, error) {
	return json.Marshal(g)
}
