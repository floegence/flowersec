package controlplane

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/issuervector"
)

type issuerAdmissionVector struct {
	Version int `json:"version"`
	Source  struct {
		Issuer          string `json:"issuer"`
		RandomBytesHex  string `json:"random_bytes_hex"`
		IssuedAtUnixSec int64  `json:"issued_at_unix_s"`
	} `json:"source"`
	ArtifactJSON              string `json:"artifact_json"`
	ChosenCandidateID         string `json:"chosen_candidate_id"`
	FSB3Hex                   string `json:"fsb3_hex"`
	AdmissionBindingHex       string `json:"admission_binding_hex"`
	AcceptorAdmissionsHashHex string `json:"acceptor_admissions_hash_hex"`
}

func init() {
	issuervector.Register(generateIssuerAdmissionVector)
}

func generateIssuerAdmissionVector() ([]byte, error) {
	const issuedAtUnix = int64(1_800_000_000)
	const candidateID = "issuer-ws"
	now := time.Unix(issuedAtUnix, 0).UTC()
	endpoints, err := NewEndpointSet(EndpointConfig{
		ID: candidateID, URL: "wss://issuer.example/flowersec/v3/direct", TLS: CAPolicy(),
	})
	if err != nil {
		return nil, err
	}
	issued, err := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)), now).IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "issuer-shared", ExpiresAt: now.Add(time.Minute)},
		Endpoints: endpoints, RendezvousGroupID: "issuer-group", ListenerAudience: "issuer-audience",
		UpstreamAddress: "127.0.0.1:9000",
	})
	if err != nil {
		return nil, err
	}
	artifact, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(issued.ArtifactJSON()))
	if err != nil {
		return nil, err
	}
	request, err := artifactv3.BuildRequest(*artifact, candidateID)
	if err != nil {
		return nil, err
	}
	frame, err := artifactv3.MarshalRequest(request)
	if err != nil {
		return nil, err
	}
	binding := artifactv3.AdmissionBinding(frame)
	admissionsHash, err := artifactv3.AcceptorAdmissionsHash([][]byte{frame})
	if err != nil {
		return nil, err
	}
	vector := issuerAdmissionVector{
		Version:                   3,
		ArtifactJSON:              string(issued.ArtifactJSON()),
		ChosenCandidateID:         candidateID,
		FSB3Hex:                   hex.EncodeToString(frame),
		AdmissionBindingHex:       hex.EncodeToString(binding[:]),
		AcceptorAdmissionsHashHex: hex.EncodeToString(admissionsHash[:]),
	}
	vector.Source.Issuer = "flowersec-go/controlplane.Issuer.IssueDirect"
	vector.Source.RandomBytesHex = "42"
	vector.Source.IssuedAtUnixSec = issuedAtUnix
	encoded, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
