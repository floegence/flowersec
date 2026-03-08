package connectcontract

import (
	"errors"
	"fmt"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/floegence/flowersec/flowersec-go/internal/channelid"
)

var (
	ErrMissingGrant       = errors.New("missing grant")
	ErrMissingConnectInfo = errors.New("missing connect info")
	ErrRoleMismatch       = errors.New("role mismatch")
	ErrMissingTunnelURL   = errors.New("missing tunnel_url")
	ErrMissingWSURL       = errors.New("missing ws_url")
	ErrMissingChannelID   = errors.New("missing channel_id")
	ErrInvalidChannelID   = errors.New("invalid channel_id")
	ErrMissingToken       = errors.New("missing token")
	ErrMissingInitExp     = errors.New("missing init_exp")
	ErrInvalidPSK         = errors.New("invalid psk")
	ErrInvalidSuite       = errors.New("invalid suite")
)

type PreparedTunnelGrant struct {
	TunnelURL          string
	ChannelID          string
	Token              string
	InitExpireAtUnixS  int64
	IdleTimeoutSeconds int32
	PSK                []byte
	Suite              e2ee.Suite
}

type PreparedDirectConnectInfo struct {
	WSURL             string
	ChannelID         string
	InitExpireAtUnixS int64
	PSK               []byte
	Suite             e2ee.Suite
}

func PrepareTunnelGrant(grant *controlv1.ChannelInitGrant, expectedRole controlv1.Role) (PreparedTunnelGrant, error) {
	if grant == nil {
		return PreparedTunnelGrant{}, ErrMissingGrant
	}
	if grant.Role != expectedRole {
		return PreparedTunnelGrant{}, ErrRoleMismatch
	}
	tunnelURL := strings.TrimSpace(grant.TunnelUrl)
	if tunnelURL == "" {
		return PreparedTunnelGrant{}, ErrMissingTunnelURL
	}
	channelID, err := normalizeChannelID(grant.ChannelId)
	if err != nil {
		return PreparedTunnelGrant{}, err
	}
	tokenStr := strings.TrimSpace(grant.Token)
	if tokenStr == "" {
		return PreparedTunnelGrant{}, ErrMissingToken
	}
	if grant.ChannelInitExpireAtUnixS <= 0 {
		return PreparedTunnelGrant{}, ErrMissingInitExp
	}
	psk, err := decodePSK(grant.E2eePskB64u)
	if err != nil {
		return PreparedTunnelGrant{}, err
	}
	allowed, err := normalizeAllowedSuites(grant.AllowedSuites)
	if err != nil {
		return PreparedTunnelGrant{}, err
	}
	suite, err := normalizeTunnelSuite(grant.DefaultSuite)
	if err != nil {
		return PreparedTunnelGrant{}, err
	}
	if _, ok := allowed[grant.DefaultSuite]; !ok {
		return PreparedTunnelGrant{}, ErrInvalidSuite
	}
	return PreparedTunnelGrant{
		TunnelURL:          tunnelURL,
		ChannelID:          channelID,
		Token:              tokenStr,
		InitExpireAtUnixS:  grant.ChannelInitExpireAtUnixS,
		IdleTimeoutSeconds: grant.IdleTimeoutSeconds,
		PSK:                psk,
		Suite:              suite,
	}, nil
}

func PrepareDirectConnectInfo(info *directv1.DirectConnectInfo) (PreparedDirectConnectInfo, error) {
	if info == nil {
		return PreparedDirectConnectInfo{}, ErrMissingConnectInfo
	}
	wsURL := strings.TrimSpace(info.WsUrl)
	if wsURL == "" {
		return PreparedDirectConnectInfo{}, ErrMissingWSURL
	}
	channelID, err := normalizeChannelID(info.ChannelId)
	if err != nil {
		return PreparedDirectConnectInfo{}, err
	}
	if info.ChannelInitExpireAtUnixS <= 0 {
		return PreparedDirectConnectInfo{}, ErrMissingInitExp
	}
	psk, err := decodePSK(info.E2eePskB64u)
	if err != nil {
		return PreparedDirectConnectInfo{}, err
	}
	suite, err := normalizeDirectSuite(info.DefaultSuite)
	if err != nil {
		return PreparedDirectConnectInfo{}, err
	}
	return PreparedDirectConnectInfo{
		WSURL:             wsURL,
		ChannelID:         channelID,
		InitExpireAtUnixS: info.ChannelInitExpireAtUnixS,
		PSK:               psk,
		Suite:             suite,
	}, nil
}

func normalizeChannelID(raw string) (string, error) {
	channelID := channelid.Normalize(raw)
	if err := channelid.Validate(channelID); err != nil {
		if errors.Is(err, channelid.ErrMissing) {
			return "", ErrMissingChannelID
		}
		return "", fmt.Errorf("%w: %v", ErrInvalidChannelID, err)
	}
	return channelID, nil
}

func decodePSK(raw string) ([]byte, error) {
	psk, err := base64url.Decode(strings.TrimSpace(raw))
	if err != nil || len(psk) != 32 {
		return nil, ErrInvalidPSK
	}
	return psk, nil
}

func normalizeAllowedSuites(in []controlv1.Suite) (map[controlv1.Suite]struct{}, error) {
	if len(in) == 0 {
		return nil, ErrInvalidSuite
	}
	out := make(map[controlv1.Suite]struct{}, len(in))
	for _, suite := range in {
		if _, err := normalizeTunnelSuite(suite); err != nil {
			return nil, err
		}
		out[suite] = struct{}{}
	}
	if len(out) == 0 {
		return nil, ErrInvalidSuite
	}
	return out, nil
}

func normalizeTunnelSuite(suite controlv1.Suite) (e2ee.Suite, error) {
	s := e2ee.Suite(suite)
	switch s {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
		return s, nil
	default:
		return 0, ErrInvalidSuite
	}
}

func normalizeDirectSuite(suite directv1.Suite) (e2ee.Suite, error) {
	s := e2ee.Suite(suite)
	switch s {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
		return s, nil
	default:
		return 0, ErrInvalidSuite
	}
}
