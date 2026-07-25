package main

import (
	"errors"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

const weaknetSystemOwner = "weaknet-system"

var weaknetSystemCases = []releaseCaseDefinition{
	{ID: "SYS-COMMON-KERNEL", Profile: "linux-netns-tc-ebpf-common-kernel"},
	{ID: "SYS-MIGRATION-REBIND", Profile: "linux-real-path-migration-rebind", Carrier: carrier.KindQUIC},
	{ID: "SYS-PMTUD-QUIC-IPV4", Profile: "kernel-pmtud-quic-ipv4", Carrier: carrier.KindQUIC},
	{ID: "SYS-PMTUD-QUIC-IPV6", Profile: "kernel-pmtud-quic-ipv6", Carrier: carrier.KindQUIC},
	{ID: "SYS-PMTUD-WSS-RECOVER-IPV4", Profile: "kernel-pmtud-wss-recover-ipv4", Carrier: carrier.KindWebSocket},
	{ID: "SYS-PMTUD-WSS-RECOVER-IPV6", Profile: "kernel-pmtud-wss-recover-ipv6", Carrier: carrier.KindWebSocket},
	{ID: "SYS-PMTUD-WSS-TIMEOUT-IPV4", Profile: "kernel-pmtud-wss-timeout-ipv4", Carrier: carrier.KindWebSocket},
	{ID: "SYS-PMTUD-WSS-TIMEOUT-IPV6", Profile: "kernel-pmtud-wss-timeout-ipv6", Carrier: carrier.KindWebSocket},
}

type weaknetSystemPlan struct {
	IPv6           bool
	Carrier        carrier.Kind
	InitialMTU     int
	ConstrainedMTU int
	ExpectTimeout  bool
	RequireRebind  bool
	RequireTCPInfo bool
	CommonMatrix   bool
}

func planWeaknetSystemCase(definition releaseCaseDefinition) (weaknetSystemPlan, error) {
	if !strings.HasPrefix(definition.ID, "SYS-") {
		return weaknetSystemPlan{}, errors.New("weaknet system case ID is invalid")
	}
	plan := weaknetSystemPlan{IPv6: strings.HasSuffix(definition.ID, "IPV6"), Carrier: definition.Carrier,
		InitialMTU: 1500, ConstrainedMTU: 1280, ExpectTimeout: strings.Contains(definition.ID, "-TIMEOUT-"),
		RequireRebind: definition.ID == "SYS-MIGRATION-REBIND", RequireTCPInfo: strings.Contains(definition.ID, "-WSS-")}
	if definition.ID == "SYS-COMMON-KERNEL" {
		plan.Carrier, plan.InitialMTU, plan.ConstrainedMTU = carrier.KindQUIC, 1280, 1280
		plan.CommonMatrix = true
	}
	if err := plan.Carrier.Validate(); err != nil {
		return weaknetSystemPlan{}, err
	}
	return plan, nil
}
