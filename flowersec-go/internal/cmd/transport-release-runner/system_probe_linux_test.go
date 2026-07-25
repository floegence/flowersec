//go:build linux

package main

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestParseWeaknetSocketEndpointsAcceptsSSVariants(t *testing.T) {
	for _, fields := range [][]string{
		{"ESTAB", "0", "0", "198.18.1.1:1234", "198.19.1.2:443", "users:((flowersec))"},
		{"0", "0", "[2001:db8:1::1]:1234", "[2001:db8:2::2]:443", "sk:123"},
	} {
		local, remote, err := parseWeaknetSocketEndpoints(fields)
		if err != nil || local.Port() != 1234 || remote.Port() != 443 {
			t.Fatalf("parse ss endpoints = %s %s, %v", local, remote, err)
		}
	}
	if _, _, err := parseWeaknetSocketEndpoints([]string{"ESTAB", "0", "0"}); err == nil {
		t.Fatal("accepted ss output without socket endpoints")
	}
}

func TestWeaknetSystemProbeUsesRealNetnsTCBPFAndCapture(t *testing.T) {
	object := os.Getenv("FLOWERSEC_BPF_OBJECT")
	if object == "" {
		t.Skip("set FLOWERSEC_BPF_OBJECT to the verifier-loadable classifier")
	}
	previousWorkerArguments := systemWorkerArguments
	t.Setenv("FLOWERSEC_TEST_WEAKNET_SYSTEM_WORKER", "1")
	systemWorkerArguments = func() []string { return []string{"-test.run=^TestWeaknetSystemWorkerProcess$"} }
	t.Cleanup(func() { systemWorkerArguments = previousWorkerArguments })
	for _, definition := range weaknetSystemCases {
		t.Run(definition.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			probe, err := runWeaknetSystemProbe(ctx, definition, object)
			if err != nil {
				t.Fatal(err)
			}
			if probe.CompletedOperations < 1 || !validClassicPCAP(probe.PCAP) ||
				probe.Kernel.Client.Packets == 0 || probe.Kernel.Server.Packets == 0 {
				t.Fatalf("system probe evidence = %+v", probe)
			}
			switch definition.ID {
			case "SYS-COMMON-KERNEL":
				if probe.Kernel.ClientQdisc.Packets+probe.Kernel.ServerQdisc.Packets == 0 {
					t.Fatal("common kernel probe has no real tc TBF packets")
				}
				burst, err := runWeaknetSystemProbeLoss(ctx, definition, object, "burst")
				if err != nil || burst.Kernel.Client.BurstLossPackets+burst.Kernel.Server.BurstLossPackets == 0 {
					t.Fatalf("burst kernel probe = %+v, %v", burst.Kernel, err)
				}
			case "SYS-MIGRATION-REBIND":
				if len(probe.QLOG) == 0 || probe.ConnectionID == "" || probe.RebindBefore == probe.RebindAfter {
					t.Fatalf("migration evidence = %+v", probe)
				}
			case "SYS-PMTUD-QUIC-IPV4", "SYS-PMTUD-QUIC-IPV6":
				evidence, err := deriveSystemPMTUDEvidence(probe.PCAP, probe.QLOG, definition.ID == "SYS-PMTUD-QUIC-IPV6")
				if err != nil || evidence.Recoveries != 1 {
					t.Fatalf("derive raw PMTUD evidence = %+v, %v", evidence, err)
				}
			}
		})
	}
}

func TestWeaknetSystemWorkerProcess(t *testing.T) {
	if os.Getenv("FLOWERSEC_TEST_WEAKNET_SYSTEM_WORKER") != "1" {
		t.Skip("helper process entrypoint")
	}
	if err := runWeaknetSystemWorker(os.Stdin, os.Stdout); err != nil {
		t.Fatal(err)
	}
}
