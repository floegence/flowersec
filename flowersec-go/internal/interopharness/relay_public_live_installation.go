package interopharness

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// RelayPublicLiveInstallation is the relay's independent installation. Public
// canonical projections come from the authority's verified original maps. Only
// the relay's own identity and TLS keys cross this boundary; the complete
// RegisteredRelayDeployment remains exclusively with the original authority.
// Byte strings use canonical JSON base64; deadline strings preserve uint64.
type RelayPublicLiveInstallation struct {
	WireRevision         int                    `json:"wire_revision"`
	Profile              string                 `json:"profile"`
	Generation           uint64                 `json:"generation"`
	Origin               string                 `json:"origin"`
	Namespaces           []NamespaceRecord      `json:"namespaces"`
	BootstrapTrustPEM    string                 `json:"bootstrap_trust_pem"`
	Binding              RelayPublicLiveBinding `json:"binding"`
	Candidate            []byte                 `json:"candidate"`
	SessionContract      []byte                 `json:"session_contract"`
	ArtifactDigest       []byte                 `json:"artifact_digest"`
	LeaseID              []byte                 `json:"lease_id"`
	InitiationNotAfterMS string                 `json:"initiation_not_after_ms"`
	SessionNotAfterMS    string                 `json:"session_not_after_ms"`
	ClientCertificate    []byte                 `json:"client_certificate"`
	ServerCertificate    []byte                 `json:"server_certificate"`
	RelayCertificate     []byte                 `json:"relay_certificate"`
	IssuerLeafDigest     []byte                 `json:"issuer_leaf_digest"`
	ClientLeafDigest     []byte                 `json:"client_leaf_digest"`
	ServerLeafDigest     []byte                 `json:"server_leaf_digest"`
	Limits               RelayPublicLiveLimits  `json:"limits"`
	RelayIdentitySeed    []byte                 `json:"relay_identity_seed"`
	NativeTLS            RelayPublicNativeTLS   `json:"native_tls"`
	RelayControl         RelayPublicLiveControl `json:"relay_control"`
}

// ParentAuthority is the verified activation winner authority. RelayAuthority
// is the independent relay ledger authority installed as deployment.Authority.
// ServerAdmissionAuthority is the separately installed endpoint admission store
// authority; a certificate subject or incoming Grant cannot select that owner.
type RelayPublicLiveBinding struct {
	Tenant                   string `json:"tenant"`
	ParentIssuer             []byte `json:"parent_issuer"`
	GrantAuthority           string `json:"grant_authority"`
	ParentAuthority          string `json:"parent_authority"`
	ServerAdmissionAuthority string `json:"server_admission_authority"`
	RelayAuthority           string `json:"relay_authority"`
	Service                  string `json:"service"`
	RelayAudience            string `json:"relay_audience"`
	RelayIdentityDigest      []byte `json:"relay_identity_digest"`
}

type RelayPublicLiveLimits struct {
	EnvelopeBytes      uint64 `json:"envelope_bytes"`
	TotalBytes         string `json:"total_bytes"`
	DatagramBytes      uint64 `json:"datagram_bytes"`
	RateBytesPerSecond string `json:"rate_bytes_per_second"`
	QueueBytes         uint64 `json:"queue_bytes"`
	PendingMappings    uint64 `json:"pending_mappings"`
	ResidentMappings   uint64 `json:"resident_mappings"`
	TotalMappings      uint64 `json:"total_mappings"`
	QueueItems         uint64 `json:"queue_items"`
}

type RelayPublicNativeTLS struct {
	TrustPEM string                 `json:"trustPEM"`
	Relay    RelayPublicTLSIdentity `json:"relay"`
}

type RelayPublicTLSIdentity struct {
	CertificatePEM string `json:"certificatePEM"`
	PrivateKeyPEM  string `json:"privateKeyPEM"`
}

type RelayPublicLiveControl struct {
	Endpoint string                `json:"endpoint"`
	Host     string                `json:"host"`
	Port     uint16                `json:"port"`
	TLS      RelayPublicControlTLS `json:"tls"`
	WorkMS   string                `json:"workMS"`
}

type RelayPublicControlTLS struct {
	CertificatePEM string `json:"certificatePEM"`
	PrivateKeyPEM  string `json:"privateKeyPEM"`
	ClientTrustPEM string `json:"clientTrustPEM"`
}

// RegisteredRemoteRelayInstallation is authority-only deployment input. Its
// TLS identity is the original issuer; its fixed leaf digest is installed at
// the relay before either endpoint can submit an original request.
type RegisteredRemoteRelayInstallation struct {
	Endpoint                 string                           `json:"endpoint"`
	ServerAdmissionAuthority string                           `json:"server_admission_authority"`
	TLS                      RegisteredControlTLSInstallation `json:"tls"`
	IssuerCertificateDER     []byte                           `json:"issuer_certificate_der"`
	Control                  RelayPublicLiveControl           `json:"control"`
	InstallationPath         string                           `json:"installation_path"`
}

func relayPublicLiveInstallation(d *RegisteredRelayDeployment, material Material, maps [4]*protocolv4.SignedMap, mapping protocolv4.RelayIssuerMapping, limits protocolv4.RelayGrantLimits) (*RelayPublicLiveInstallation, error) {
	if d == nil || d.LiveControl == nil || d.RemoteRelay == nil || maps[0] == nil || maps[3] == nil {
		return nil, errors.New("verified original remote relay projection is required")
	}
	if mapping.Grants[0].Namespace.Authority != mapping.Grants[1].Namespace.Authority {
		return nil, errors.New("public live relay requires one installed Grant authority")
	}
	session, err := maps[0].SessionParameters()
	if err != nil {
		return nil, err
	}
	lease, ok := maps[0].Field("lease_id").ByteString()
	if !ok || len(lease) != 16 {
		return nil, errors.New("verified original lease is missing")
	}
	initiation, ok := maps[0].Field("initiation_not_after_ms").Uint()
	sessionEnd, endOK := maps[0].Field("session_not_after_ms").Uint()
	candidate := maps[0].Field("candidates").Index(0).Encoded()
	contract := maps[0].Field("session_contract").Encoded()
	if !ok || !endOK || initiation == 0 || sessionEnd < initiation || len(candidate) == 0 || len(contract) == 0 {
		return nil, errors.New("verified original candidate geometry is incomplete")
	}
	relayDigest, err := maps[3].Digest("certificate_digest")
	if err != nil {
		return nil, err
	}
	issuerLeaf := sha256.Sum256(d.RemoteRelay.IssuerCertificateDER)
	clientLeaf := sha256.Sum256(d.LiveControl.ClientControlCertificateDER)
	serverLeaf := sha256.Sum256(d.LiveControl.ServerControlCertificateDER)
	if issuerLeaf == clientLeaf || issuerLeaf == serverLeaf || clientLeaf == serverLeaf {
		return nil, errors.New("remote live relay requires distinct fixed issuer and endpoint control identities")
	}
	control := d.RemoteRelay.Control
	control.Endpoint = d.RemoteRelay.Endpoint
	return &RelayPublicLiveInstallation{WireRevision: 4, Profile: session.Profile, Generation: material.Generation.Generation, Origin: d.Origin, Namespaces: append([]NamespaceRecord(nil), material.Namespaces...), BootstrapTrustPEM: d.ControlTrustPEM,
		Binding:   RelayPublicLiveBinding{Tenant: mapping.Parent.Tenant, ParentIssuer: append([]byte(nil), mapping.ParentIssuer[:]...), GrantAuthority: mapping.Grants[0].Namespace.Authority, ParentAuthority: mapping.Activation.WinnerAuthority, RelayAuthority: d.Authority, ServerAdmissionAuthority: d.RemoteRelay.ServerAdmissionAuthority, Service: mapping.Service, RelayAudience: mapping.RelayAudience, RelayIdentityDigest: append([]byte(nil), relayDigest[:]...)},
		Candidate: append([]byte(nil), candidate...), SessionContract: append([]byte(nil), contract...), ArtifactDigest: append([]byte(nil), session.ArtifactDigest[:]...), LeaseID: append([]byte(nil), lease...), InitiationNotAfterMS: strconv.FormatUint(initiation, 10), SessionNotAfterMS: strconv.FormatUint(sessionEnd, 10),
		ClientCertificate: append([]byte(nil), material.ClientCertificate...), ServerCertificate: append([]byte(nil), material.ServerCertificate...), RelayCertificate: append([]byte(nil), d.RelayCertificate...), IssuerLeafDigest: append([]byte(nil), issuerLeaf[:]...), ClientLeafDigest: append([]byte(nil), clientLeaf[:]...), ServerLeafDigest: append([]byte(nil), serverLeaf[:]...),
		Limits:            RelayPublicLiveLimits{EnvelopeBytes: limits.EnvelopeBytes, TotalBytes: strconv.FormatUint(limits.TotalBytes, 10), DatagramBytes: limits.DatagramBytes, RateBytesPerSecond: strconv.FormatUint(limits.RateBytesPerSecond, 10), QueueBytes: limits.QueueBytes, PendingMappings: limits.PendingMappings, ResidentMappings: limits.ResidentMappings, TotalMappings: limits.TotalMappings, QueueItems: limits.QueueItems},
		RelayIdentitySeed: append([]byte(nil), d.RelayIdentitySeed...), NativeTLS: RelayPublicNativeTLS{TrustPEM: d.NativeTLS.TrustPEM, Relay: RelayPublicTLSIdentity{CertificatePEM: d.NativeTLS.Relay.CertificatePEM, PrivateKeyPEM: d.NativeTLS.Relay.PrivateKeyPEM}}, RelayControl: control}, nil
}

// ReleaseOwnedPrivateMaterial retires the authority's retained projection only
// after its signing and publication owners have joined. The seed is a detached
// byte copy; PEM strings may share backing storage with the installed input.
func (p *RelayPublicLiveInstallation) ReleaseOwnedPrivateMaterial() {
	if p == nil {
		return
	}
	clear(p.RelayIdentitySeed)
	p.RelayIdentitySeed = nil
	p.NativeTLS.Relay.PrivateKeyPEM = ""
	p.RelayControl.TLS.PrivateKeyPEM = ""
}

// Publish installs once at the configured path before authority-prepared. It
// never overwrites an installation or promotes an endpoint publication into it.
func (p *RelayPublicLiveInstallation) Publish(path string) (err error) {
	if p == nil || path == "" || len(path) > 4096 || !filepath.IsAbs(path) {
		return errors.New("independent relay installation needs one absolute configured path")
	}
	wire, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer clear(wire)
	if len(wire) == 0 || len(wire) > 4194304 {
		return errors.New("public relay installation exceeds its bounded file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			err = errors.Join(err, os.Remove(path))
		}
	}()
	n, err := file.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = errors.Join(directory.Sync(), directory.Close())
	if err == nil {
		installed = true
	}
	return err
}
