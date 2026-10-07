// Package interopharness supplies explicit test-authority material for engineering
// peers. These records are an application binding, not Flowersec wire maps or
// production authority to trust an enclosed key.
package interopharness

import (
	"encoding/json"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"net/url"
	"strconv"
)

const WireRevision = 4
const MaxNamespaces = 16
const MaxTunnelAuthorizations = 2

// Material carries complete canonical signed maps. JSON byte strings are base64.
// Identity seeds belong only to this explicitly enabled engineering peer. A
// consumer must bootstrap each independently pinned namespace with its own fresh
// nonce through BootstrapURL before admitting any credential.
type Material struct {
	WireRevision           int                               `json:"wire_revision"`
	Profile                string                            `json:"profile"`
	Source                 string                            `json:"source"`
	Generation             Generation                        `json:"generation"`
	Role                   uint8                             `json:"role"`
	Artifact               []byte                            `json:"artifact"`
	Activation             []byte                            `json:"activation"`
	ClientCertificate      []byte                            `json:"client_certificate"`
	ServerCertificate      []byte                            `json:"server_certificate"`
	Route                  []byte                            `json:"route"`
	RouteDigest            []byte                            `json:"route_digest"`
	ActivationSigningKeyID string                            `json:"activation_signing_key_id"`
	IdentitySeed           []byte                            `json:"identity_seed"`
	DHSeed                 []byte                            `json:"dh_seed"`
	Namespaces             []NamespaceRecord                 `json:"namespaces"`
	Tunnels                []TunnelMaterial                  `json:"tunnels"`
	RelayDeployment        protocolv4.RelayDeploymentBinding `json:"relay_deployment"`
	LiveControlBaseURL     string                            `json:"live_control_base_url,omitempty"`
}

// releaseOwnedMaterial runs after all users of this decoded material have
// joined. Artifact bytes include private session inputs as well as public maps.
// Shallow endpoint projections share those bytes and must be retired together.
func releaseOwnedMaterial(m *Material) {
	if m == nil {
		return
	}
	clear(m.IdentitySeed)
	m.IdentitySeed = nil
	clear(m.DHSeed)
	m.DHSeed = nil
	clear(m.Artifact)
	m.Artifact = nil
}

type Generation struct {
	Source     []byte `json:"source"`
	Generation uint64 `json:"generation"`
}

// NamespaceRecord pins the authority independently of a credential. The HTTP
// bootstrap response is the complete signed TrustBootstrapResponse, with the
// exact fresh nonce supplied by the requesting owner; StateURL returns canonical
// RevocationState bytes. Neither URL is a key locator inferred from a credential.
type NamespaceRecord struct {
	Tenant        string `json:"tenant"`
	Authority     string `json:"authority"`
	Generation    uint64 `json:"generation"`
	RootKeyID     []byte `json:"root_key_id"`
	RootPublicKey []byte `json:"root_public_key"`
	BootstrapURL  string `json:"bootstrap_url"`
	StateURL      string `json:"state_url"`
}

type BootstrapRequest struct {
	Tenant    string `json:"tenant"`
	Authority string `json:"authority"`
	Nonce     []byte `json:"nonce"`
}

type BootstrapResponse struct {
	Response []byte `json:"response"`
	State    []byte `json:"state"`
}

type TunnelMaterial struct {
	CandidateIndex   uint64             `json:"candidate_index"`
	Role             uint8              `json:"role"`
	Grant            []byte             `json:"grant,omitempty"`
	LiveGrant        *LiveGrantMaterial `json:"live_grant,omitempty"`
	RelayCertificate []byte             `json:"relay_certificate"`
	GrantNamespace   uint8              `json:"grant_namespace"`
	RelayNamespace   uint8              `json:"relay_namespace"`
}

// LiveGrantMaterial is independently installed preparation policy. It carries
// no signed Grant or activation capability. Each consumer resolves the issuer
// and policy through its fresh namespace owner before deriving preparation.
// Decimal strings preserve every uint64 bit across JavaScript consumers.
type LiveGrantMaterial struct {
	Authority                string `json:"authority"`
	IssuerKeyID              []byte `json:"issuer_key_id"`
	Audience                 string `json:"audience"`
	Service                  string `json:"service"`
	RevocationPolicyID       string `json:"revocation_policy_id"`
	RevocationPolicyRevision string `json:"revocation_policy_revision"`
	MaxNotAfterMS            string `json:"max_not_after_ms"`
}

func canonicalMaterialUint(value string, positive bool) (uint64, error) {
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(number, 10) != value || positive && number == 0 {
		return 0, errors.New("invalid current engineering decimal integer")
	}
	return number, nil
}
func materialIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		alpha := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if !alpha && (index == 0 || character != '.' && character != '_' && character != ':' && character != '/' && character != '@' && character != '-') {
			return false
		}
	}
	return true
}
func materialHTTPS(value string) bool {
	if len(value) == 0 || len(value) > 2048 {
		return false
	}
	endpoint, err := url.Parse(value)
	return err == nil && endpoint.Scheme == "https" && endpoint.Host != "" && endpoint.User == nil && endpoint.Fragment == "" && endpoint.RawQuery == "" && endpoint.Opaque == ""
}

// TunnelAuthorization is one original current grant and its complete endpoint
// and relay identities. Relay admission verifies it against VerificationRecords;
// the caller's previous decision/lease hints have no authorization meaning.
type TunnelAuthorization struct {
	CandidateIndex      uint64 `json:"candidate_index"`
	Role                uint8  `json:"role"`
	Grant               []byte `json:"grant"`
	EndpointCertificate []byte `json:"endpoint_certificate"`
	RelayCertificate    []byte `json:"relay_certificate"`
	GrantNamespace      uint8  `json:"grant_namespace"`
	EndpointNamespace   uint8  `json:"endpoint_namespace"`
	RelayNamespace      uint8  `json:"relay_namespace"`
}

func (m Material) JSON() (string, error) {
	if m.WireRevision != WireRevision || m.Role > 1 || len(m.Namespaces) == 0 || len(m.Namespaces) > MaxNamespaces ||
		len(m.Tunnels) > 16 || len(m.Generation.Source) != 16 || m.Generation.Generation == 0 ||
		len(m.IdentitySeed) != 32 || len(m.DHSeed) != 32 || len(m.RouteDigest) != 32 ||
		len(m.Artifact) == 0 || len(m.ClientCertificate) == 0 || len(m.ServerCertificate) == 0 {
		return "", errors.New("invalid current engineering material")
	}
	if m.Profile != protocolv4.DHProfileX25519 && m.Profile != protocolv4.DHProfileP256 {
		return "", errors.New("unsupported current engineering crypto profile")
	}
	if len(m.Artifact) > 65536 || len(m.ClientCertificate) > 16384 || len(m.ServerCertificate) > 16384 || len(m.Route) == 0 || len(m.Route) > 16384 {
		return "", errors.New("current engineering map exceeds its envelope")
	}
	switch m.Source {
	case "preauthorized_pool":
		if len(m.Activation) == 0 || len(m.Activation) > 65536 || m.LiveControlBaseURL != "" {
			return "", errors.New("pool material requires its original activation")
		}
	case "live_authority":
		if len(m.Activation) != 0 || !materialHTTPS(m.LiveControlBaseURL) {
			return "", errors.New("live material requires its independently installed control endpoint and pending activation")
		}
	default:
		return "", errors.New("unsupported current engineering source")
	}
	for _, record := range m.Namespaces {
		if !materialIdentifier(record.Tenant) || !materialIdentifier(record.Authority) || record.Generation == 0 || len(record.RootKeyID) != 16 || len(record.RootPublicKey) != 32 || !materialHTTPS(record.BootstrapURL) || !materialHTTPS(record.StateURL) {
			return "", errors.New("invalid independently pinned namespace record")
		}
	}
	slots := make(map[[2]uint64]bool, len(m.Tunnels))
	for _, entry := range m.Tunnels {
		slot := [2]uint64{entry.CandidateIndex, uint64(entry.Role)}
		if entry.CandidateIndex >= 16 || entry.Role > 1 || slots[slot] || int(entry.GrantNamespace) >= len(m.Namespaces) || int(entry.RelayNamespace) >= len(m.Namespaces) || len(entry.RelayCertificate) == 0 || len(entry.RelayCertificate) > 16384 {
			return "", errors.New("invalid current tunnel material slot")
		}
		slots[slot] = true
		if m.Source == "preauthorized_pool" {
			if entry.LiveGrant != nil || len(entry.Grant) == 0 || len(entry.Grant) > 65536 {
				return "", errors.New("pool tunnel requires its original issued Grant")
			}
		} else {
			pending := entry.LiveGrant
			if len(entry.Grant) != 0 || pending == nil || !materialIdentifier(pending.Authority) || pending.Authority != m.Namespaces[entry.GrantNamespace].Authority || len(pending.IssuerKeyID) != 16 || !materialIdentifier(pending.Audience) || !materialIdentifier(pending.Service) || !materialIdentifier(pending.RevocationPolicyID) {
				return "", errors.New("live tunnel requires its independently installed pending Grant scope")
			}
			if _, err := canonicalMaterialUint(pending.RevocationPolicyRevision, true); err != nil {
				return "", err
			}
			if _, err := canonicalMaterialUint(pending.MaxNotAfterMS, true); err != nil {
				return "", err
			}
		}
	}
	if (len(m.Tunnels) > 0 || m.RelayDeployment != (protocolv4.RelayDeploymentBinding{})) && (m.RelayDeployment.Profile == "" || m.RelayDeployment.RouteDigest == ([32]byte{}) || m.RelayDeployment.RouteDigest != [32]byte(m.RouteDigest)) {
		return "", errors.New("current tunnel material lacks matching independent relay deployment")
	}
	wire, err := json.Marshal(m)
	defer clear(wire)
	return string(wire), err
}

// MarshalJSON retains the original relay installation before Grant issuance.
// Direct consumers do not receive an empty relay profile as installed policy.
func (m Material) MarshalJSON() ([]byte, error) {
	type originalMaterial Material
	var deployment *protocolv4.RelayDeploymentBinding
	if len(m.Tunnels) > 0 || m.RelayDeployment != (protocolv4.RelayDeploymentBinding{}) {
		binding := m.RelayDeployment
		deployment = &binding
	}
	return json.Marshal(struct {
		originalMaterial
		RelayDeployment *protocolv4.RelayDeploymentBinding `json:"relay_deployment,omitempty"`
	}{originalMaterial: originalMaterial(m), RelayDeployment: deployment})
}
