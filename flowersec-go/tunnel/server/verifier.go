package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
)

var ErrUnknownTenant = errors.New("unknown tenant")

// VerifiedToken is the attach token after tenant selection and signature verification.
type VerifiedToken struct {
	TenantID string
	Audience string
	Issuer   string
	Payload  token.Payload
}

// AttachVerifier verifies tunnel attach tokens and supports hot reload.
type AttachVerifier interface {
	Verify(tokenStr string, now time.Time, skew time.Duration) (VerifiedToken, error)
	Reload() error
}

type staticVerifier struct {
	audience string
	issuer   string
	keyFile  string
	keys     *IssuerKeyset
}

// NewStaticVerifier builds the legacy single-tenant verifier.
func NewStaticVerifier(audience string, issuer string, issuerKeysFile string) (AttachVerifier, error) {
	issuerKeysFile = strings.TrimSpace(issuerKeysFile)
	if issuerKeysFile == "" {
		return nil, configError("missing issuer keys file")
	}
	keys, err := LoadIssuerKeysetFile(issuerKeysFile)
	if err != nil {
		return nil, err
	}
	return &staticVerifier{
		audience: strings.TrimSpace(audience),
		issuer:   strings.TrimSpace(issuer),
		keyFile:  issuerKeysFile,
		keys:     keys,
	}, nil
}

func (v *staticVerifier) Verify(tokenStr string, now time.Time, skew time.Duration) (VerifiedToken, error) {
	payload, err := token.Verify(tokenStr, v.keys, token.VerifyOptions{
		Now:       now,
		Audience:  v.audience,
		Issuer:    v.issuer,
		ClockSkew: skew,
	})
	if err != nil {
		return VerifiedToken{}, err
	}
	return VerifiedToken{
		Audience: v.audience,
		Issuer:   v.issuer,
		Payload:  payload,
	}, nil
}

func (v *staticVerifier) Reload() error {
	keys, err := LoadIssuerKeysetFile(v.keyFile)
	if err != nil {
		return err
	}
	v.keys.Replace(keys.keys)
	return nil
}

type tenantFile struct {
	Tenants []tenantFileEntry `json:"tenants"`
}

type tenantFileEntry struct {
	ID             string `json:"id,omitempty"`
	Audience       string `json:"aud"`
	Issuer         string `json:"iss"`
	IssuerKeysFile string `json:"issuer_keys_file"`
}

type tenantVerifierEntry struct {
	id       string
	audience string
	issuer   string
	keys     *IssuerKeyset
}

type multiTenantVerifier struct {
	path string

	mu      sync.RWMutex
	tenants map[string]tenantVerifierEntry
}

// NewMultiTenantVerifier loads verifier tenants from a JSON file.
func NewMultiTenantVerifier(path string) (AttachVerifier, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, configError("missing tenants file")
	}
	v := &multiTenantVerifier{path: path}
	if err := v.Reload(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *multiTenantVerifier) Verify(tokenStr string, now time.Time, skew time.Duration) (VerifiedToken, error) {
	parsed, signed, sig, err := token.Parse(tokenStr)
	if err != nil {
		return VerifiedToken{}, err
	}
	scopeKey := tenantScopeKey(parsed.Aud, parsed.Iss)

	v.mu.RLock()
	tenant, ok := v.tenants[scopeKey]
	v.mu.RUnlock()
	if !ok {
		return VerifiedToken{}, ErrUnknownTenant
	}

	payload, err := token.VerifyParsed(parsed, signed, sig, tenant.keys, token.VerifyOptions{
		Now:       now,
		Audience:  tenant.audience,
		Issuer:    tenant.issuer,
		ClockSkew: skew,
	})
	if err != nil {
		return VerifiedToken{}, err
	}
	return VerifiedToken{
		TenantID: tenant.id,
		Audience: tenant.audience,
		Issuer:   tenant.issuer,
		Payload:  payload,
	}, nil
}

func (v *multiTenantVerifier) Reload() error {
	tenants, err := loadTenantVerifierEntries(v.path)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.tenants = tenants
	v.mu.Unlock()
	return nil
}

func loadTenantVerifierEntries(path string) (map[string]tenantVerifierEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw tenantFile
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	if len(raw.Tenants) == 0 {
		return nil, errors.New("empty tenants file")
	}

	out := make(map[string]tenantVerifierEntry, len(raw.Tenants))
	for _, item := range raw.Tenants {
		audience := strings.TrimSpace(item.Audience)
		issuer := strings.TrimSpace(item.Issuer)
		keysFile := strings.TrimSpace(item.IssuerKeysFile)
		if audience == "" || issuer == "" || keysFile == "" {
			return nil, errors.New("invalid tenant entry")
		}
		scopeKey := tenantScopeKey(audience, issuer)
		if _, exists := out[scopeKey]; exists {
			return nil, fmt.Errorf("duplicate tenant scope: aud=%q iss=%q", audience, issuer)
		}
		keys, err := LoadIssuerKeysetFile(keysFile)
		if err != nil {
			return nil, fmt.Errorf("load tenant keyset: %w", err)
		}
		out[scopeKey] = tenantVerifierEntry{
			id:       strings.TrimSpace(item.ID),
			audience: audience,
			issuer:   issuer,
			keys:     keys,
		}
	}
	return out, nil
}

func tenantScopeKey(audience string, issuer string) string {
	return strings.TrimSpace(audience) + "\x00" + strings.TrimSpace(issuer)
}
