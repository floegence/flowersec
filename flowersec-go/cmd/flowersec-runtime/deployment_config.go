package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// deploymentConfig names independent host inputs rather than recoverable SDK
// owners. Private keys, namespace roots and history approvals are installation
// input; neither a credential nor a failed Open can replace any of them.
type deploymentConfig struct {
	WireRevision uint8              `json:"wire_revision"`
	Role         string             `json:"role"`
	Resources    resourcev4.Config  `json:"resources"`
	Environment  []byte             `json:"environment_id"`
	Clock        clockSpec          `json:"clock"`
	Namespaces   []namespaceSpec    `json:"namespaces"`
	Stores       [3]storeSpec       `json:"stores"`
	Pool         poolSpec           `json:"pool"`
	TLS          controlTLSSpec     `json:"control_tls"`
	Relay        relaySpec          `json:"relay"`
	Direct       *directRuntimeSpec `json:"direct,omitempty"`
	ShutdownMS   uint32             `json:"shutdown_ms"`
}
type clockSpec struct {
	Qualification    string         `json:"qualification_id"`
	Incarnation      []byte         `json:"incarnation"`
	Profile          timev4.Profile `json:"profile"`
	LowerMS          uint64         `json:"lower_ms"`
	UpperMS          uint64         `json:"upper_ms"`
	DriftToleranceMS uint64         `json:"drift_tolerance_ms"`
}
type namespaceSpec struct {
	Root                     protocolv4.NamespaceTrustRoot       `json:"root"`
	TrustLimits              protocolv4.NamespaceTrustLimits     `json:"trust_limits"`
	BootstrapLimits          protocolv4.NamespaceBootstrapLimits `json:"bootstrap_limits"`
	URL                      string                              `json:"bootstrap_url"`
	Address                  string                              `json:"bootstrap_address"`
	TLSRootsFile             string                              `json:"tls_roots_file"`
	TLSClientCertificateFile string                              `json:"tls_client_certificate_file"`
	TLSClientKeyFile         string                              `json:"tls_client_key_file"`
}
type historyApproval struct {
	Authority      string `json:"authority"`
	StoreID        []byte `json:"store_id"`
	Generation     uint64 `json:"generation"`
	Epoch          uint64 `json:"epoch"`
	NotAfterMS     uint64 `json:"not_after_ms"`
	Provision      bool   `json:"provision"`
	PathDigest     []byte `json:"path_digest"`
	DatabaseDigest []byte `json:"database_digest"`
	WALDigest      []byte `json:"wal_digest"`
	Signature      []byte `json:"signature"`
}
type storeSpec struct {
	Path       string                  `json:"path"`
	Identity   ledgerv4.SQLiteIdentity `json:"identity"`
	Limits     ledgerv4.SQLiteLimits   `json:"limits"`
	HistoryKey []byte                  `json:"history_public_key"`
	History    historyApproval         `json:"history_approval"`
}
type signerSpec struct {
	SeedFile string `json:"seed_file"`
}
type poolSpec struct {
	Tenant                 string                             `json:"tenant"`
	Audience               string                             `json:"audience"`
	CryptoProfile          string                             `json:"crypto_profile"`
	SourceIncarnation      []byte                             `json:"source_incarnation"`
	PoolDigest             []byte                             `json:"pool_digest"`
	ClientIdentityDigest   []byte                             `json:"client_identity_digest"`
	ServerIdentityDigest   []byte                             `json:"server_identity_digest"`
	OwnerFence             ledgerv4.TopUpSourceFence          `json:"owner_fence"`
	FenceKey               protocolv4.TopUpFenceAuthority     `json:"fence_key"`
	FenceSigner            signerSpec                         `json:"fence_signer"`
	ArtifactIssuer         protocolv4.DirectIssuerConfig      `json:"artifact_issuer"`
	ArtifactSigner         signerSpec                         `json:"artifact_signer"`
	Trust                  [3]uint8                           `json:"trust_namespaces"`
	IssuePolicy            protocolv4.DirectIssuePolicyConfig `json:"issue_policy"`
	ReadNamespaces         []protocolv4.NamespaceReference    `json:"read_namespaces"`
	AuthenticationFile     string                             `json:"authentication_file"`
	MaxOutstanding         uint32                             `json:"max_outstanding"`
	StateBytes             uint64                             `json:"state_bytes"`
	ActivationSigningKeyID string                             `json:"activation_signing_key_id"`
	ActivationSigner       signerSpec                         `json:"activation_signer"`
	Budget                 protocolv4.PoolAttemptLimits       `json:"attempt_budget"`
	Indices                []uint64                           `json:"candidate_indices"`
	Routes                 []grantRouteSpec                   `json:"grant_routes"`
	TopUpContract          []byte                             `json:"top_up_contract"`
	AckContract            []byte                             `json:"ack_contract"`
	ApplicationErrorCode   uint32                             `json:"application_error_code"`
	RetirementSkewMS       uint64                             `json:"retirement_skew_ms"`
}
type grantRouteSpec struct {
	Candidate        uint8                          `json:"candidate_index"`
	GrantIssuers     [2][16]byte                    `json:"grant_issuers"`
	GrantSigners     [2]signerSpec                  `json:"grant_signers"`
	GrantTrust       [2]uint8                       `json:"grant_namespaces"`
	RelayTrust       uint8                          `json:"relay_namespace"`
	RelayCertificate []byte                         `json:"relay_certificate"`
	Service          string                         `json:"service"`
	RelayAudience    string                         `json:"relay_audience"`
	Limits           [2]protocolv4.RelayGrantLimits `json:"limits"`
}
type controlTLSSpec struct {
	Listen                string `json:"listen"`
	CertificateFile       string `json:"certificate_file"`
	PrivateKeyFile        string `json:"private_key_file"`
	ClientRootsFile       string `json:"client_roots_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
}
type relaySpec struct {
	Route      []byte                            `json:"route"`
	Deployment protocolv4.RelayDeploymentBinding `json:"deployment"`
	Instance   []byte                            `json:"instance"`
	Generation uint64                            `json:"generation"`
	Signer     signerSpec                        `json:"signer"`
	Legs       [2]relayLegSpec                   `json:"legs"`
}
type relayLegSpec struct {
	Carrier         uint64 `json:"carrier"`
	Origin          string `json:"origin,omitempty"`
	Listen          string `json:"listen"`
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
	TLSRootsFile    string `json:"tls_roots_file"`
}

type directRuntimeSpec struct {
	Tenant            string                              `json:"tenant"`
	Materials         []directMaterialSpec                `json:"materials"`
	Listeners         []directListenerSpec                `json:"listeners"`
	Admission         []directAdmissionSpec               `json:"admission"`
	Core              sessionv4.SessionCoreConfig         `json:"core"`
	Limits            sessionv4.EstablishmentLimits       `json:"establishment_limits"`
	LocalCapabilities uint64                              `json:"local_capabilities"`
	BindingMode       uint64                              `json:"binding_mode"`
	Executor          sessionv4.ApplicationExecutorConfig `json:"executor"`
	Streams           []directStreamSpec                  `json:"streams"`
	HandshakeMS       uint64                              `json:"handshake_ms"`
	MaxRecordBytes    uint32                              `json:"max_admission_record_bytes"`
	Services          *directServiceSpec                  `json:"services,omitempty"`
	Client            *directClientSpec                   `json:"client,omitempty"`
}
type directServiceSpec struct {
	RPC       sessionv4.RPCServicesConfig `json:"rpc"`
	Methods   []directMethodSpec          `json:"methods"`
	Histories []directExecutionSpec       `json:"histories"`
}
type directMethodSpec struct {
	ContractFile    string                         `json:"contract_file"`
	Namespace       string                         `json:"namespace"`
	Type            uint32                         `json:"type"`
	WorkClass       sessionv4.ApplicationWorkClass `json:"work_class"`
	AdmissionOffers []timev4.Interval              `json:"admission_offers,omitempty"`
	Stream          *directStreamingSpec           `json:"stream,omitempty"`
	Upstream        directStreamSpec               `json:"upstream"`
}
type directStreamingSpec struct {
	Kind     string         `json:"kind"`
	Metadata map[string]any `json:"metadata"`
}

type directExecutionSpec struct {
	Service                                            rpcv4.ExecutionService `json:"service"`
	CallerAuthorities                                  [][32]byte             `json:"caller_authorities"`
	Records, Active                                    uint32
	RuntimeBytes, WorkRuntimeBytes, ResultRuntimeBytes uint64
	Durable                                            *directDurableSpec `json:"durable,omitempty"`
}
type directDurableSpec struct {
	Store         storeSpec                         `json:"store"`
	ContinuityKey []byte                            `json:"continuity_public_key"`
	Continuity    directExecutionContinuityApproval `json:"continuity_approval"`
}
type directExecutionContinuityApproval struct {
	Identity       ledgerv4.SQLiteIdentity         `json:"identity"`
	Service        ledgerv4.SQLiteExecutionService `json:"service"`
	Epoch          uint64                          `json:"epoch"`
	DatabaseDigest []byte                          `json:"database_digest"`
	WorkFenced     bool                            `json:"previous_work_fenced"`
	Authority      string                          `json:"authority"`
	NotAfterMS     uint64                          `json:"not_after_ms"`
	Signature      []byte                          `json:"signature"`
}
type directClientSpec struct {
	Ingress     []directClientIngressSpec `json:"ingress"`
	Providers   []directListenerSpec      `json:"providers"`
	LiveControl *namespaceSpec            `json:"live_control,omitempty"`
}
type directClientIngressSpec struct {
	Material  uint16         `json:"material"`
	Address   string         `json:"address"`
	Kind      string         `json:"kind"`
	Metadata  map[string]any `json:"metadata"`
	Slots     uint16         `json:"slots"`
	TimeoutMS uint64         `json:"timeout_ms"`
}

type directMaterialSpec struct {
	ArtifactFile           string                       `json:"artifact_file"`
	ActivationFile         string                       `json:"activation_file"`
	ClientCertificateFile  string                       `json:"client_certificate_file"`
	ServerCertificateFile  string                       `json:"server_certificate_file"`
	IdentitySigner         signerSpec                   `json:"identity_signer"`
	DHSeedFile             string                       `json:"dh_seed_file"`
	Source                 string                       `json:"source"`
	ActivationSigningKeyID string                       `json:"activation_signing_key_id"`
	Trust                  [3]uint8                     `json:"trust_namespaces"`
	Generation             protocolv4MaterialGeneration `json:"generation"`
	CandidateIndex         uint64                       `json:"candidate_index"`
	Attempt                [16]byte                     `json:"attempt"`
}
type protocolv4MaterialGeneration struct {
	Source     [16]byte `json:"source"`
	Generation uint64   `json:"generation"`
}
type directAdmissionSpec struct {
	Tenant         string   `json:"tenant"`
	Audience       string   `json:"audience"`
	Profile        string   `json:"profile"`
	Source         string   `json:"source"`
	Issuer         [16]byte `json:"issuer"`
	ServerIdentity [32]byte `json:"server_identity"`
	SpendAuthority string   `json:"spend_authority"`
	SigningKey     string   `json:"signing_key"`
}
type directListenerSpec struct {
	Material        uint16                    `json:"material"`
	Address         string                    `json:"address"`
	CertificateFile string                    `json:"certificate_file"`
	PrivateKeyFile  string                    `json:"private_key_file"`
	TLSRootsFile    string                    `json:"tls_roots_file"`
	Origin          string                    `json:"origin,omitempty"`
	QUIC            rawquic.OwnedOptions      `json:"quic"`
	WebTransport    webtransport.OwnedOptions `json:"webtransport"`
	WebSocket       websocket.Options         `json:"websocket"`
}
type directStreamSpec struct {
	Kind      string `json:"kind"`
	Slots     uint32 `json:"slots"`
	Network   string `json:"network"`
	Address   string `json:"address"`
	TimeoutMS uint64 `json:"timeout_ms"`
}

func loadDeploymentConfig(path string) (deploymentConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return deploymentConfig{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return deploymentConfig{}, &ConfigError{Field: "config", Err: errors.New("configuration exceeds 1 MiB")}
	}
	defer clear(raw)
	if err = rejectDuplicateRuntimeJSON(raw); err != nil {
		return deploymentConfig{}, &ConfigError{Field: "config", Err: err}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var c deploymentConfig
	if err = decoder.Decode(&c); err != nil {
		return c, &ConfigError{Field: "config", Err: errors.New("invalid current deployment JSON")}
	}
	if err = requireJSONEOF(decoder); err != nil {
		return c, err
	}
	if c.WireRevision != 4 || c.Role != "relay" && c.Role != "direct-server" && c.Role != "direct-client" || len(c.Environment) != 16 || c.Resources.ProfileRevision == ([32]byte{}) || c.ShutdownMS == 0 || c.ShutdownMS > 300000 || len(c.Namespaces) == 0 || len(c.Namespaces) > 16 {
		return c, &ConfigError{Field: "config", Err: errors.New("explicit v4 deployment role, owners and finite limits are required")}
	}
	if c.Role == "relay" && (c.Direct != nil || len(c.Pool.SourceIncarnation) != 16 || len(c.Pool.PoolDigest) != 32 || len(c.Pool.ClientIdentityDigest) != 32 || len(c.Pool.ServerIdentityDigest) != 32 || len(c.Pool.TopUpContract) != 32 || len(c.Pool.AckContract) != 32 || len(c.Relay.Instance) != 16 || len(c.Pool.Indices) == 0 || len(c.Pool.Indices) > 16) {
		return c, errors.New("relay requires its independent original Pool owners")
	}
	if c.Role == "direct-server" || c.Role == "direct-client" {
		if err := validateDirectRuntimeSpec(c.Direct, len(c.Namespaces)); err != nil {
			return c, err
		}
		if (c.Role == "direct-client") != (c.Direct.Client != nil) {
			return c, errors.New("direct client ingress must match the original deployment role")
		}
	}
	if c.Clock.Qualification == "" || len(c.Clock.Incarnation) != 16 || c.Clock.LowerMS == 0 || c.Clock.UpperMS < c.Clock.LowerMS || c.Clock.DriftToleranceMS == 0 {
		return c, &ConfigError{Field: "clock", Err: errors.New("independent qualified clock input is required")}
	}
	seen := map[string]bool{}
	storeCount := 3
	if c.Role != "relay" {
		storeCount = 1
	}
	for _, store := range c.Stores[:storeCount] {
		if !filepath.IsAbs(store.Path) || filepath.Clean(store.Path) != store.Path || seen[store.Path] || len(store.HistoryKey) != 32 || len(store.History.Signature) != 64 {
			return c, &ConfigError{Field: "stores", Err: errors.New("independent physical stores and signed history approvals are required")}
		}
		seen[store.Path] = true
	}
	if c.Direct != nil && c.Direct.Services != nil {
		for _, history := range c.Direct.Services.Histories {
			if history.Durable == nil {
				continue
			}
			durable := history.Durable
			store := durable.Store
			if !filepath.IsAbs(store.Path) || filepath.Clean(store.Path) != store.Path || seen[store.Path] || len(store.HistoryKey) != 32 || len(store.History.Signature) != 64 || len(durable.ContinuityKey) != 32 || len(durable.Continuity.Signature) != 64 || bytes.Equal(durable.ContinuityKey, store.HistoryKey) {
				return c, errors.New("durable execution requires a separate original store and independent signed continuity approval")
			}
			seen[store.Path] = true
		}
	}
	for _, index := range c.Pool.Trust {
		if int(index) >= len(c.Namespaces) {
			return c, errors.New("credential namespace selector is outside configured roots")
		}
	}
	if c.Pool.ArtifactIssuer.Authority != nil || c.Pool.ArtifactIssuer.Signer != nil || c.Pool.ArtifactIssuer.Clock != nil || c.Pool.IssuePolicy.Trust != nil || c.Pool.IssuePolicy.Clock != nil {
		return c, errors.New("SDK owners must be constructed from original host inputs")
	}
	return c, nil
}

// DisallowUnknownFields does not reject duplicate keys. All host authority
// inputs use exactly one spelling and one original value before decoding.
func rejectDuplicateRuntimeJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	tokens := 0
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 64 || tokens >= 32768 {
			return errors.New("configuration JSON exceeds its nesting or token limit")
		}
		value, err := decoder.Token()
		tokens++
		if err != nil {
			return err
		}
		delimiter, composite := value.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				name, err := decoder.Token()
				tokens++
				if err != nil {
					return err
				}
				key, ok := name.(string)
				if !ok {
					return errors.New("invalid configuration object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("duplicate configuration object key")
				}
				seen[key] = struct{}{}
				if err = visit(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid configuration object")
			}
		case '[':
			for decoder.More() {
				if err = visit(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid configuration array")
			}
		default:
			return errors.New("invalid configuration delimiter")
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("configuration contains trailing JSON")
	}
	return nil
}

func validateDirectRuntimeSpec(c *directRuntimeSpec, namespaces int) error {
	if c == nil || c.Tenant == "" || len(c.Materials) == 0 || len(c.Materials) > 1024 || c.Client == nil && len(c.Listeners) == 0 || len(c.Listeners) > 16 || len(c.Admission) == 0 || len(c.Admission) > 64 || (len(c.Streams) == 0 && c.Services == nil && c.Client == nil) || len(c.Streams) > 128 || c.HandshakeMS == 0 || c.HandshakeMS > 90000 || c.MaxRecordBytes < 1024 || c.MaxRecordBytes > 1<<20 || c.Core.Clock != nil || c.Core.Handlers.Plan != nil || c.Core.Session != (protocolv4.ArtifactSessionParameters{}) || c.BindingMode != 1 {
		return errors.New("direct server requires original materials, stable admission mapping, native listeners and bounded current stream registrations")
	}
	for _, material := range c.Materials {
		if material.Source != "preauthorized_pool" && material.Source != "live_authority" || material.Generation.Source == ([16]byte{}) || material.Generation.Generation == 0 || material.CandidateIndex >= 16 || material.ActivationSigningKeyID == "" {
			return errors.New("direct material lacks original source, generation or activation signer")
		}
		for _, index := range material.Trust {
			if int(index) >= namespaces {
				return errors.New("direct material namespace is outside independent root pins")
			}
		}
	}
	seenAdmission := map[directAdmissionSpec]bool{}
	for _, record := range c.Admission {
		if record.Tenant != c.Tenant || record.Audience == "" || (record.Profile != protocolv4.DHProfileX25519 && record.Profile != protocolv4.DHProfileP256) || (record.Source != "preauthorized_pool" && record.Source != "live_authority") || record.Issuer == ([16]byte{}) || record.ServerIdentity == ([32]byte{}) || record.SpendAuthority == "" || record.SigningKey == "" || seenAdmission[record] {
			return errors.New("direct admission requires unique complete stable mappings for its exact tenant")
		}
		seenAdmission[record] = true
	}
	if c.Services != nil {
		services := c.Services
		rpc := services.RPC
		if len(services.Methods) == 0 || len(services.Methods) > 128 || len(services.Histories) > 64 || rpc.Root != nil || rpc.Clock != nil || rpc.Routes.Clock != nil || rpc.ExecutionRegistry != nil || rpc.ManagementResolver != nil || len(rpc.Accounts) != 0 || len(rpc.Methods) != 0 || len(rpc.StreamMethods) != 0 || len(rpc.NotificationMethods) != 0 || len(rpc.ExecutionServices) != 0 || len(rpc.Routes.Methods) != 0 || rpc.Session.Valid() {
			return errors.New("service aggregate must contain only original finite numeric tuning and current method registrations")
		}
		for _, method := range services.Methods {
			if method.ContractFile == "" || method.Namespace == "" || method.Type == 0 || method.WorkClass > sessionv4.ApplicationResident || method.Upstream.Network != "tcp" || method.Upstream.Address == "" || method.Upstream.TimeoutMS == 0 || method.Upstream.TimeoutMS > 3600000 {
				return errors.New("service method requires an exact original contract and fixed bounded upstream")
			}
			if len(method.AdmissionOffers) > 8 {
				return errors.New("durable method admits at most eight explicitly installed windows")
			}
			for _, offer := range method.AdmissionOffers {
				if offer.LowerMS >= offer.UpperMS {
					return errors.New("durable admission windows require exact positive bounds")
				}
			}
		}
		historyNamespaces := map[string]bool{}
		for _, history := range services.Histories {
			if history.Service.Tenant != c.Tenant || history.Service.Audience == "" || history.Service.Namespace == "" || len(history.CallerAuthorities) == 0 || len(history.CallerAuthorities) > 64 || historyNamespaces[history.Service.Namespace] {
				return errors.New("execution history must retain one independently installed logical authority per namespace")
			}
			historyNamespaces[history.Service.Namespace] = true
		}
	}
	if c.Client != nil {
		if len(c.Listeners) != 0 || len(c.Client.Ingress) == 0 || len(c.Client.Ingress) > len(c.Materials) || len(c.Client.Providers) != len(c.Materials) {
			return errors.New("direct client requires a finite original ingress/provider mapping")
		}
		for index, provider := range c.Client.Providers {
			if provider.Material != uint16(index) || provider.Address == "" || provider.TLSRootsFile == "" || len(provider.Origin) > 4096 {
				return errors.New("direct client providers must retain their exact material selector and independent native address/trust")
			}
		}
		seenClient := map[uint16]bool{}
		for _, ingress := range c.Client.Ingress {
			if int(ingress.Material) >= len(c.Materials) || seenClient[ingress.Material] || ingress.Kind == "" || ingress.Address == "" || ingress.Slots == 0 || ingress.Slots > 128 || ingress.TimeoutMS == 0 || ingress.TimeoutMS > 3600000 {
				return errors.New("direct client ingress must bind one original material and finite local stream capacity")
			}
			seenClient[ingress.Material] = true
		}
	}
	for _, listener := range c.Listeners {
		if int(listener.Material) >= len(c.Materials) || listener.Address == "" || listener.CertificateFile == "" || listener.PrivateKeyFile == "" {
			return errors.New("direct native listeners require independent numeric addresses, TLS and provider inputs")
		}
	}
	seen := map[string]bool{}
	for _, stream := range c.Streams {
		if stream.Kind == "" || seen[stream.Kind] || stream.Slots == 0 || stream.Slots > 1024 || stream.Network != "tcp" || stream.Address == "" || stream.TimeoutMS == 0 || stream.TimeoutMS > 3600000 {
			return errors.New("direct upstream stream registration is missing or duplicated")
		}
		seen[stream.Kind] = true
	}
	return nil
}
