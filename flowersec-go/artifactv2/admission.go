package artifactv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
)

type directRequestWire struct {
	CandidateSetHashBase64URL    string               `json:"candidate_set_hash_b64u"`
	Candidates                   []CanonicalCandidate `json:"candidates"`
	ChannelID                    string               `json:"channel_id"`
	ChosenCandidateID            string               `json:"chosen_candidate_id"`
	ListenerAudience             string               `json:"listener_audience"`
	Profile                      string               `json:"profile"`
	RendezvousGroupID            string               `json:"rendezvous_group_id"`
	RoutingToken                 string               `json:"routing_token"`
	SessionContractHashBase64URL string               `json:"session_contract_hash_b64u"`
}

type tunnelRequestWire struct {
	AttachToken                  string               `json:"attach_token"`
	CandidateSetHashBase64URL    string               `json:"candidate_set_hash_b64u"`
	Candidates                   []CanonicalCandidate `json:"candidates"`
	ChannelID                    string               `json:"channel_id"`
	ChosenCandidateID            string               `json:"chosen_candidate_id"`
	EndpointInstanceID           string               `json:"endpoint_instance_id"`
	ListenerAudience             string               `json:"listener_audience"`
	Profile                      string               `json:"profile"`
	RendezvousGroupID            string               `json:"rendezvous_group_id"`
	Role                         uint8                `json:"role"`
	SessionContractHashBase64URL string               `json:"session_contract_hash_b64u"`
}

func BuildRequest(artifact Artifact, chosenCandidateID string) (Request, error) {
	if err := validateArtifact(artifact); err != nil {
		return Request{}, err
	}
	candidates, _, candidateHash, err := CanonicalizeCandidates(artifact.Path.Kind, artifact.Path.Candidates)
	if err != nil {
		return Request{}, err
	}
	request := requestFromValidatedArtifact(artifact, candidates, candidateHash, chosenCandidateID)
	if err := validateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func requestFromValidatedArtifact(artifact Artifact, candidates []CanonicalCandidate, candidateHash [32]byte, chosenCandidateID string) Request {
	request := Request{
		PathKind:            artifact.Path.Kind,
		Profile:             artifact.Profile,
		ChannelID:           artifact.Session.ChannelID,
		SessionContractHash: artifact.Session.ContractHash,
		RendezvousGroupID:   artifact.Path.RendezvousGroupID,
		Candidates:          candidates,
		CandidateSetHash:    candidateHash,
		ChosenCandidateID:   chosenCandidateID,
		ListenerAudience:    artifact.Path.ListenerAudience,
	}
	if artifact.Path.Kind == PathDirect {
		request.RoutingToken = artifact.Path.RoutingToken
	} else {
		request.Role = artifact.Path.Role
		request.EndpointInstanceID = artifact.Path.LocalEndpointInstanceID
		request.AttachToken = artifact.Path.Token
	}
	return request
}

func MarshalRequest(request Request) ([]byte, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	payload, err := marshalRequestPayload(request)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxCanonicalFSB2Payload {
		return nil, ErrFSB2PayloadTooLarge
	}
	out := make([]byte, FSB2HeaderSize+len(payload))
	copy(out[0:4], "FSB2")
	out[4] = 2
	out[5] = pathKindCode(request.PathKind)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(payload)))
	copy(out[12:], payload)
	return out, nil
}

func ReadRequest(reader io.Reader) (*DecodedRequest, error) {
	var header [FSB2HeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrInvalidFSB2, err)
	}
	if string(header[0:4]) != "FSB2" || header[4] != 2 || header[6] != 0 || header[7] != 0 {
		return nil, ErrInvalidFSB2
	}
	kind, err := pathKindFromCode(header[5])
	if err != nil {
		return nil, err
	}
	payloadLength := binary.BigEndian.Uint32(header[8:12])
	if payloadLength > MaxCanonicalFSB2Payload {
		return nil, ErrFSB2PayloadTooLarge
	}
	if payloadLength == 0 {
		return nil, ErrInvalidFSB2
	}
	payload := make([]byte, int(payloadLength))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrInvalidFSB2, err)
	}
	request, err := decodeRequestPayload(kind, payload)
	if err != nil {
		return nil, err
	}
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	canonical, err := marshalRequestPayload(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(payload, canonical) {
		return nil, ErrNonCanonicalFSB2
	}
	raw := make([]byte, FSB2HeaderSize+len(payload))
	copy(raw, header[:])
	copy(raw[FSB2HeaderSize:], payload)
	return &DecodedRequest{Request: request, Raw: raw, LocalAdmissionBinding: AdmissionBinding(raw)}, nil
}

func ParseRequest(raw []byte) (*DecodedRequest, error) {
	reader := bytes.NewReader(raw)
	request, err := ReadRequest(reader)
	if err != nil {
		return nil, err
	}
	if reader.Len() != 0 {
		return nil, fmt.Errorf("%w: bytes after declared payload", ErrInvalidFSB2)
	}
	return request, nil
}

func AdmissionBinding(rawFSB2 []byte) [32]byte {
	preimage := make([]byte, 0, len("flowersec-v2-admission\x00")+len(rawFSB2))
	preimage = append(preimage, "flowersec-v2-admission\x00"...)
	preimage = append(preimage, rawFSB2...)
	return sha256.Sum256(preimage)
}

func validateRequest(request Request) error {
	if request.PathKind != PathDirect && request.PathKind != PathTunnel || request.Profile != Profile {
		return fmt.Errorf("%w: path/profile", ErrInvalidFSB2)
	}
	if !validRegistryID(request.ChannelID, 128) || !validRegistryID(request.RendezvousGroupID, 128) || !validRegistryID(request.ListenerAudience, 128) {
		return fmt.Errorf("%w: common registry id", ErrInvalidFSB2)
	}
	source := make([]Candidate, 0, len(request.Candidates))
	for _, candidate := range request.Candidates {
		source = append(source, Candidate{
			ID: candidate.ID, Carrier: candidate.Carrier, URL: candidate.NormalizedURL,
			NormalizedURL: candidate.NormalizedURL, WireProfile: candidate.WireProfile,
		})
	}
	canonicalCandidates, _, candidateHash, err := CanonicalizeCandidates(request.PathKind, source)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFSB2, err)
	}
	if !slices.Equal(canonicalCandidates, request.Candidates) || candidateHash != request.CandidateSetHash {
		return fmt.Errorf("%w: candidate set hash or ordering", ErrInvalidFSB2)
	}
	chosen := false
	for _, candidate := range request.Candidates {
		if candidate.ID == request.ChosenCandidateID {
			chosen = true
			break
		}
	}
	if !chosen {
		return fmt.Errorf("%w: chosen candidate", ErrInvalidFSB2)
	}
	switch request.PathKind {
	case PathDirect:
		if !validASCII(request.RoutingToken, MaxAdmissionCredentialBytes) || request.Role != 0 || request.EndpointInstanceID != "" || request.AttachToken != "" {
			return fmt.Errorf("%w: direct variant", ErrInvalidFSB2)
		}
	case PathTunnel:
		if (request.Role != 1 && request.Role != 2) || !validRegistryID(request.EndpointInstanceID, 128) || !validASCII(request.AttachToken, MaxAdmissionCredentialBytes) || request.RoutingToken != "" {
			return fmt.Errorf("%w: tunnel variant", ErrInvalidFSB2)
		}
	}
	return nil
}

func marshalRequestPayload(request Request) ([]byte, error) {
	if request.PathKind == PathDirect {
		return canonicalJSON(directRequestWire{
			CandidateSetHashBase64URL: encode32(request.CandidateSetHash),
			Candidates:                request.Candidates, ChannelID: request.ChannelID,
			ChosenCandidateID: request.ChosenCandidateID, ListenerAudience: request.ListenerAudience,
			Profile: request.Profile, RendezvousGroupID: request.RendezvousGroupID,
			RoutingToken: request.RoutingToken, SessionContractHashBase64URL: encode32(request.SessionContractHash),
		})
	}
	return canonicalJSON(tunnelRequestWire{
		AttachToken: request.AttachToken, CandidateSetHashBase64URL: encode32(request.CandidateSetHash),
		Candidates: request.Candidates, ChannelID: request.ChannelID,
		ChosenCandidateID: request.ChosenCandidateID, EndpointInstanceID: request.EndpointInstanceID,
		ListenerAudience: request.ListenerAudience, Profile: request.Profile,
		RendezvousGroupID: request.RendezvousGroupID, Role: request.Role,
		SessionContractHashBase64URL: encode32(request.SessionContractHash),
	})
}

func decodeRequestPayload(kind PathKind, payload []byte) (Request, error) {
	if kind == PathDirect {
		var wire directRequestWire
		if err := decodeStrictJSON(payload, &wire); err != nil {
			return Request{}, fmt.Errorf("%w: direct payload: %v", ErrInvalidFSB2, err)
		}
		sessionHash, candidateHash, err := decodeRequestHashes(wire.SessionContractHashBase64URL, wire.CandidateSetHashBase64URL)
		if err != nil {
			return Request{}, err
		}
		return Request{
			PathKind: kind, Profile: wire.Profile, ChannelID: wire.ChannelID,
			SessionContractHash: sessionHash, RendezvousGroupID: wire.RendezvousGroupID,
			Candidates: wire.Candidates, CandidateSetHash: candidateHash,
			ChosenCandidateID: wire.ChosenCandidateID, ListenerAudience: wire.ListenerAudience,
			RoutingToken: wire.RoutingToken,
		}, nil
	}
	var wire tunnelRequestWire
	if err := decodeStrictJSON(payload, &wire); err != nil {
		return Request{}, fmt.Errorf("%w: tunnel payload: %v", ErrInvalidFSB2, err)
	}
	sessionHash, candidateHash, err := decodeRequestHashes(wire.SessionContractHashBase64URL, wire.CandidateSetHashBase64URL)
	if err != nil {
		return Request{}, err
	}
	return Request{
		PathKind: kind, Profile: wire.Profile, ChannelID: wire.ChannelID,
		SessionContractHash: sessionHash, RendezvousGroupID: wire.RendezvousGroupID,
		Candidates: wire.Candidates, CandidateSetHash: candidateHash,
		ChosenCandidateID: wire.ChosenCandidateID, ListenerAudience: wire.ListenerAudience,
		Role: wire.Role, EndpointInstanceID: wire.EndpointInstanceID, AttachToken: wire.AttachToken,
	}, nil
}

func decodeRequestHashes(sessionValue, candidateValue string) ([32]byte, [32]byte, error) {
	sessionHash, err := decode32(sessionValue)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: session contract hash", ErrInvalidFSB2)
	}
	candidateHash, err := decode32(candidateValue)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: candidate set hash", ErrInvalidFSB2)
	}
	return sessionHash, candidateHash, nil
}

func MarshalResponse(response AdmissionResponse, reasons ReasonRegistry) ([]byte, error) {
	if err := validateResponse(response, reasons); err != nil {
		return nil, err
	}
	out := make([]byte, FSA2HeaderSize+len(response.Reason))
	copy(out[0:4], "FSA2")
	out[4] = 2
	out[5] = byte(response.Status)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(response.Reason)))
	copy(out[8:], response.Reason)
	return out, nil
}

func ReadResponse(reader io.Reader, reasons ReasonRegistry) (AdmissionResponse, error) {
	var header [FSA2HeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return AdmissionResponse{}, fmt.Errorf("%w: header: %v", ErrInvalidFSA2, err)
	}
	if string(header[0:4]) != "FSA2" || header[4] != 2 {
		return AdmissionResponse{}, ErrInvalidFSA2
	}
	reasonLength := binary.BigEndian.Uint16(header[6:8])
	if reasonLength > MaxAdmissionReasonBytes {
		return AdmissionResponse{}, ErrInvalidFSA2
	}
	reason := make([]byte, int(reasonLength))
	if _, err := io.ReadFull(reader, reason); err != nil {
		return AdmissionResponse{}, fmt.Errorf("%w: reason: %v", ErrInvalidFSA2, err)
	}
	response := AdmissionResponse{Status: AdmissionStatus(header[5]), Reason: string(reason)}
	if err := validateResponse(response, reasons); err != nil {
		return AdmissionResponse{}, err
	}
	return response, nil
}

func ParseResponse(raw []byte, reasons ReasonRegistry) (AdmissionResponse, error) {
	reader := bytes.NewReader(raw)
	response, err := ReadResponse(reader, reasons)
	if err != nil {
		return AdmissionResponse{}, err
	}
	if reader.Len() != 0 {
		return AdmissionResponse{}, fmt.Errorf("%w: bytes after declared reason", ErrInvalidFSA2)
	}
	return response, nil
}

func validateResponse(response AdmissionResponse, reasons ReasonRegistry) error {
	switch response.Status {
	case AdmissionSuccess:
		if response.Reason != "" {
			return ErrInvalidFSA2
		}
		return nil
	case AdmissionReject, AdmissionRetryable:
		if !validReasonToken(response.Reason) {
			return ErrInvalidFSA2
		}
		if _, ok := reasons[response.Reason]; !ok {
			return fmt.Errorf("%w: %s", ErrUnknownAdmissionCode, response.Reason)
		}
		return nil
	default:
		return ErrInvalidFSA2
	}
}

func validReasonToken(reason string) bool {
	if len(reason) < 1 || len(reason) > MaxAdmissionReasonBytes || reason[0] < 'a' || reason[0] > 'z' {
		return false
	}
	for i := 1; i < len(reason); i++ {
		c := reason[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

func pathKindCode(kind PathKind) byte {
	if kind == PathDirect {
		return 1
	}
	if kind == PathTunnel {
		return 2
	}
	return 0
}

func pathKindFromCode(code byte) (PathKind, error) {
	switch code {
	case 1:
		return PathDirect, nil
	case 2:
		return PathTunnel, nil
	default:
		return "", ErrInvalidFSB2
	}
}
