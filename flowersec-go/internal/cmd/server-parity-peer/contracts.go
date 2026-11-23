package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
)

type parityContracts struct {
	Namespace string            `json:"namespace"`
	QueryID   uint32            `json:"query_type_id"`
	Contracts map[uint32]string `json:"contracts"`
}

func registerContractQuery(handlers parityRPCRegistrar) error {
	data, err := os.ReadFile("../examples/parity-contracts.json")
	if err != nil {
		return err
	}
	var manifest parityContracts
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	installed := [...]uint32{echoRPC, notifyRPC, completeRPC, datagramRPC}
	if manifest.Namespace == "" || manifest.QueryID == 0 || len(manifest.Contracts) != len(installed) {
		return fmt.Errorf("incomplete parity declaration")
	}
	for _, id := range installed {
		encoded := manifest.Contracts[id]
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(decoded) == 0 || base64.StdEncoding.EncodeToString(decoded) != encoded {
			return fmt.Errorf("invalid parity contract for method %d", id)
		}
	}
	return handlers.HandleRPC(manifest.QueryID, manifest.query)
}

func (manifest parityContracts) query(_ context.Context, raw json.RawMessage) (any, *flowersec.RPCError) {
	var request struct {
		Namespace string   `json:"namespace"`
		TypeIDs   []uint32 `json:"type_ids"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if !json.Valid(raw) || decoder.Decode(&request) != nil || len(request.TypeIDs) == 0 || len(request.TypeIDs) > len(manifest.Contracts) {
		return nil, &flowersec.RPCError{Code: 400, Message: "invalid parity query"}
	}
	result := make([]string, 0, len(request.TypeIDs))
	for _, id := range request.TypeIDs {
		contract, ok := manifest.Contracts[id]
		if !ok || request.Namespace != manifest.Namespace {
			return nil, &flowersec.RPCError{Code: 404, Message: "contract unavailable"}
		}
		result = append(result, contract)
	}
	return map[string][]string{"contracts": result}, nil
}
