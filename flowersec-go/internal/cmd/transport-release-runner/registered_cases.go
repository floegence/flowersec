package main

import (
	"errors"
	"fmt"
	"sort"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

const conformanceFullOwner = "transport-conformance-full"
const capacityOwner = "bench-transport-capacity"
const soakOwner = "bench-transport-soak"
const browserSmokeOwner = "transport-browser-smoke"

var soakCases = []releaseCaseDefinition{{ID: "CAP-SOAK-5M", Profile: "five-minute-weaknet-soak-v1"}}

var browserSmokeCases = []releaseCaseDefinition{
	{ID: "BN-N5", Profile: "webtransport-native-isolation", BrowserTopology: browserDirectTopology},
	{ID: "BS-C7", Profile: "direct-webtransport-browser-go", BrowserTopology: browserDirectTopology},
	{ID: "BS-C8", Profile: "tunnel-webtransport-wss", BrowserTopology: string(tunnelworkload.BrowserTunnelWTWSS)},
}

var conformanceFullCases = []releaseCaseDefinition{
	{ID: "CF-C1", Profile: "release-cell-1", Carrier: carrier.KindWebSocket, Suite: protocolv2.SuiteChaCha20Poly1305},
	{ID: "CF-C2", Profile: "release-cell-2", Carrier: carrier.KindQUIC, Suite: protocolv2.SuiteAES256GCM},
	{ID: "CF-C3", Profile: "release-cell-3", Topology: tunnelworkload.TopologyWW, Suite: protocolv2.SuiteChaCha20Poly1305},
	{ID: "CF-C4", Profile: "release-cell-4", Topology: tunnelworkload.TopologyQQ, Suite: protocolv2.SuiteAES256GCM},
	{ID: "CF-C5", Profile: "release-cell-5", Topology: tunnelworkload.TopologyWQ, Suite: protocolv2.SuiteChaCha20Poly1305},
	{ID: "CF-C6", Profile: "release-cell-6", Topology: tunnelworkload.TopologyQW, Suite: protocolv2.SuiteAES256GCM},
	{ID: "CF-C7", Profile: "release-cell-7", Carrier: carrier.KindWebSocket, Suite: protocolv2.SuiteAES256GCM},
	{ID: "CF-C8", Profile: "release-cell-8", Carrier: carrier.KindQUIC, Suite: protocolv2.SuiteChaCha20Poly1305},
}

var weaknetFullCases = []releaseCaseDefinition{
	{ID: "WF-BYTE-FULL", Profile: "userspace-byte-fault-fidelity"},
	{ID: "WF-CLEANUP-FULL", Profile: "userspace-cancel-cleanup-conservation"},
	{ID: "WF-UDP-FULL", Profile: "userspace-udp-fault-fidelity"},
	{ID: "WF-UDP-RANDOM-LOSS", Profile: "userspace-udp-seeded-random-loss"},
}

func registeredCasesForOwner(owner, mode string) ([]releaseCaseDefinition, error) {
	if owner == quicNativeRaceOwner && mode == "race" {
		return append([]releaseCaseDefinition(nil), nativeRaceCases...), nil
	}
	if mode != "normal" {
		return nil, fmt.Errorf("owner %q does not support mode %q", owner, mode)
	}
	switch owner {
	case conformanceSmokeOwner:
		return append([]releaseCaseDefinition(nil), conformanceSmokeCases...), nil
	case conformanceFullOwner:
		return append([]releaseCaseDefinition(nil), conformanceFullCases...), nil
	case weaknetFullOwner:
		return append([]releaseCaseDefinition(nil), weaknetFullCases...), nil
	case weaknetSystemOwner:
		return append([]releaseCaseDefinition(nil), weaknetSystemCases...), nil
	case quicNativeSmokeOwner:
		return append([]releaseCaseDefinition(nil), nativeSmokeCases...), nil
	case quicNativeProofOwner:
		return append([]releaseCaseDefinition(nil), nativeProofCases...), nil
	case browserSmokeOwner:
		return append([]releaseCaseDefinition(nil), browserSmokeCases...), nil
	case capacityOwner:
		definitions := make([]releaseCaseDefinition, 0, len(frozenCapacityCases))
		for _, capacity := range frozenCapacityCases {
			definitions = append(definitions, releaseCaseDefinition{ID: capacity.ID, Profile: capacity.Profile})
		}
		sort.Slice(definitions, func(left, right int) bool { return definitions[left].ID < definitions[right].ID })
		return definitions, nil
	case soakOwner:
		return append([]releaseCaseDefinition(nil), soakCases...), nil
	default:
		return nil, fmt.Errorf("release case producer is unavailable for owner %q mode %q", owner, mode)
	}
}

func validateReleaseCaseDefinitions(definitions []releaseCaseDefinition) error {
	if len(definitions) == 0 {
		return errors.New("release case suite has no definitions")
	}
	previous := ""
	for _, definition := range definitions {
		if definition.ID == "" || definition.Profile == "" || previous >= definition.ID {
			return errors.New("release case definitions must have unique ascending IDs and non-empty profiles")
		}
		previous = definition.ID
	}
	return nil
}

func releaseCaseContext(mode, id string) string {
	if mode == "race" {
		return "race case " + id
	}
	return "case " + id
}
