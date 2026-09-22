package protocolv4

import (
	"encoding/hex"
	"encoding/json"
	"sync"
)

// ManagementSpec fixes the SDK-only M channel and its two method contracts.
// No method binding or business authority is selected by peer input.
type ManagementSpec struct {
	Kind             string
	Profile          string `json:"application_profile"`
	Opener           Direction
	MetadataBytes    uint32 `json:"metadata_bytes"`
	ReceiveLimit     uint64 `json:"initial_receive_limit"`
	LifetimeChannels uint32 `json:"lifetime_channels"`
	Running, Pending uint32
	MaxPayload       uint32 `json:"max_payload_bytes"`
	MaxLifetimeMS    uint64 `json:"max_message_lifetime_ms"`
	Query, Cancel    ManagementMethod
}
type ManagementMethod struct {
	Type                      uint32
	Contract                  [32]byte
	RequestKind, ResponseKind string
}

var runtimeManagement = sync.OnceValues(func() (ManagementSpec, error) {
	var wire struct {
		Management struct {
			ManagementSpec
			Methods map[string]struct {
				Type         uint32
				RequestKind  string `json:"request_kind"`
				ResponseKind string `json:"response_kind"`
				ContractHex  string `json:"contract_hex"`
				DigestHex    string `json:"contract_digest_hex"`
			}
		}
	}
	if err := json.Unmarshal([]byte(ApplicationHeaderRegistryJSON), &wire); err != nil {
		return ManagementSpec{}, err
	}
	s := wire.Management.ManagementSpec
	if s.Kind != "flowersec.execution-management.v4" || s.Profile != "execution" || s.Opener != ClientToServer || s.MetadataBytes != 0 || s.ReceiveLimit != 16384 || s.LifetimeChannels != 16 || s.Running != 2 || s.Pending != 2 || s.MaxPayload != 16384 || s.MaxLifetimeMS != 30000 || len(wire.Management.Methods) != 2 {
		return ManagementSpec{}, CBORFailure("registry_unresolved")
	}
	for _, name := range []string{"query", "cancel"} {
		m := wire.Management.Methods[name]
		contract, err := hex.DecodeString(m.ContractHex)
		if err != nil {
			return ManagementSpec{}, err
		}
		digest, err := hex.DecodeString(m.DigestHex)
		if err != nil || len(digest) != 32 || len(contract) == 0 {
			return ManagementSpec{}, CBORFailure("registry_unresolved")
		}
		expected, err := fullMapDigest("service_contract_digest", "ServiceContract", contract)
		if err != nil {
			return ManagementSpec{}, err
		}
		var declared [32]byte
		copy(declared[:], digest)
		if expected != declared {
			return ManagementSpec{}, CBORFailure("registry_unresolved")
		}
		method := ManagementMethod{Type: m.Type, RequestKind: m.RequestKind, ResponseKind: m.ResponseKind}
		copy(method.Contract[:], digest)
		if name == "query" {
			s.Query = method
		} else {
			s.Cancel = method
		}
	}
	if s.Query.Type != 1 || s.Cancel.Type != 2 || s.Query.Contract == s.Cancel.Contract || s.Query.RequestKind != "query_operation_request" || s.Query.ResponseKind != "query_operation_response" || s.Cancel.RequestKind != "request_cancel_request" || s.Cancel.ResponseKind != "request_cancel_response" {
		return ManagementSpec{}, CBORFailure("registry_unresolved")
	}
	return s, nil
})

func Management() (ManagementSpec, error) { return runtimeManagement() }
